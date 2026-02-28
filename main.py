import asyncio
import hashlib
import hmac
import json
import os
from fastapi import FastAPI, HTTPException, Query, Header, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, desc, case
from argon2 import PasswordHasher
from models import Session as SessionModel
from argon2.exceptions import VerifyMismatchError
from datetime import datetime, timedelta, timezone
from schema import AuthRequest, ChatRequest, MessageRequest, PublishRequest, PKeyResponse, SignupRequest, EpochRequest
import secrets

from models import init_db, SessionLocal, User, Chat, Message, UserKey, ChatEpoch

app = FastAPI()

app.mount("/app", StaticFiles(directory="static", html=True), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ph = PasswordHasher()

# ── WebSocket connection manager ──────────────────────────────────────

class ConnectionManager:
    """Tracks active WebSocket connections per chat."""

    def __init__(self):
        # chat_id -> dict[user_id, WebSocket]
        self.active: dict[int, dict[int, WebSocket]] = {}

    async def connect(self, chat_id: int, user_id: int, ws: WebSocket):
        await ws.accept()
        self.active.setdefault(chat_id, {})[user_id] = ws

    def disconnect(self, chat_id: int, user_id: int):
        chat_conns = self.active.get(chat_id)
        if chat_conns:
            chat_conns.pop(user_id, None)
            if not chat_conns:
                del self.active[chat_id]

    async def broadcast(self, chat_id: int, payload: dict, exclude_user_id: int | None = None):
        """Send a JSON message to every user connected to *chat_id*."""
        chat_conns = self.active.get(chat_id)
        if not chat_conns:
            return
        data = json.dumps(payload)
        stale: list[int] = []
        for uid, ws in chat_conns.items():
            if uid == exclude_user_id:
                continue
            try:
                await ws.send_text(data)
            except Exception:
                stale.append(uid)
        for uid in stale:
            chat_conns.pop(uid, None)

manager = ConnectionManager()

# ── Startup ───────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_db()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

try:
    SERVER_KEY = os.environ.get("SERVER_KEY").encode("utf-8")
except Exception:
    raise RuntimeError("SERVER_KEY environment variable must be set")

async def require_auth(
    authorization: str = Header(...),
    db: Session = Depends(get_db),
    device_Id: str = Header(..., alias="X-Device-ID")
) -> User:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization.removeprefix("Bearer ").strip()
    token_hash = hmac.new(
        SERVER_KEY,
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    token = None

    session = (
        db.query(SessionModel)
        .filter(
            SessionModel.session_token_hash == token_hash,
            SessionModel.expires_at > datetime.now(timezone.utc),
            SessionModel.device_id == device_Id,
        )
        .one_or_none()
    )

    if not session:
        raise HTTPException(status_code=401, detail="Unauthorized")

    user = (
        db.query(User)
        .filter(User.id == session.user_id)
        .one_or_none()
    )

    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return user

@app.get("/")
async def read_root():
    return {"ping": "pong"}


# Authentication endpoints
@app.post("/auth/signup", status_code=201)
async def signup(payload: SignupRequest, db: Session = Depends(get_db)):
    existing_user = (
        db.query(User)
        .filter(User.username == payload.username)
        .one_or_none()
    )

    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    password_hash = ph.hash(payload.password)

    user = User(
        username=payload.username,
        password_hash=password_hash,
    )

    db.add(user)
    db.flush()  # get user.id without committing

    user_key = UserKey(
        user_id=user.id,
        identity_pub=payload.identity_pub,
        encrypted_identity_priv=payload.encrypted_identity_priv,
        kdf_salt=payload.kdf_salt,
        aead_nonce=payload.aead_nonce,
    )

    db.add(user_key)
    db.commit()
    db.refresh(user)

    return {
        "id": user.id,
        "username": user.username,
    }
    

@app.post("/auth/login")
async def login(
    payload: AuthRequest, 
    db: Session = Depends(get_db),
    device_Id: str = Header(..., alias="X-Device-ID"),
    user_Agent: str | None = Header(None),
):
    user = (
        db.query(User)
        .filter(User.username == payload.username)
        .one_or_none()
    )

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    try:
        ph.verify(user.password_hash, payload.password)
    except VerifyMismatchError:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = secrets.token_urlsafe(32)

    token_hash = hmac.new(
        SERVER_KEY,
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    session = SessionModel(
        user_id=user.id,
        device_id=device_Id,
        session_token_hash=token_hash,
        user_agent=user_Agent,
        last_accessed=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )

    db.add(session)
    db.commit()

    return {"token": token}

@app.post("/auth/logout")
async def logout(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    session = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == user.id)
        .one_or_none()
    )

    db.delete(session)
    db.commit()

    return {"status": "logged out"}

@app.get("/auth/keyblob")
async def get_encrypted_key_blob(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    user_key = (
        db.query(UserKey)
        .filter(UserKey.user_id == user.id)
        .one_or_none()
    )

    if not user_key:
        raise HTTPException(
            status_code=404,
            detail="Identity key material not found",
        )

    return {
        "identity_pub": user_key.identity_pub,
        "encrypted_identity_priv": user_key.encrypted_identity_priv,
        "kdf_salt": user_key.kdf_salt,
        "aead_nonce": user_key.aead_nonce,
    }

@app.get("/auth/me")
async def get_me(user: User = Depends(require_auth)):
        return {"id": user.id, "username": user.username}

# Account endpoints
@app.get("/users/sessions")
async def list_sessions(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
    authorization: str = Header(...),
    device_id: str = Header(..., alias="X-Device-ID"),
):
    token = authorization.removeprefix("Bearer ").strip()
    current_token_hash = hmac.new(
        SERVER_KEY,
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    sessions = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == user.id)
        .all()
    )

    return [
        {
            "id": s.id,
            "device_id": s.device_id,
            "user_agent": s.user_agent,
            "last_accessed": s.last_accessed,
            "created_at": s.created_at,
            "expires_at": s.expires_at,
            "current": (
                s.session_token_hash == current_token_hash and
                s.device_id == device_id
            ),
        }
        for s in sessions
    ]

@app.get("/users/search")
async def search_users(
    q: str = Query(..., min_length=1),
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    matches = (
        db.query(User)
        .filter(
            User.username.ilike(f"%{q}%"),
            User.id != user.id,
        )
        .order_by(
            # exact match first, then starts-with, then the rest
            case(
                (func.lower(User.username) == q.lower(), 0),
                (func.lower(User.username).like(f"{q.lower()}%"), 1),
                else_=2,
            ),
            func.length(User.username),
        )
        .limit(7)
        .all()
    )

    return [{"id": u.id, "username": u.username} for u in matches]


@app.delete("/users/sessions/revoke/{session_id}")
async def revoke_session(
    session_id: int,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    session = (
        db.query(SessionModel)
        .filter(
            SessionModel.id == session_id,
            SessionModel.user_id == user.id,
        )
        .one_or_none()
    )

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    db.delete(session)
    db.commit()

    return {"status": "revoked"}

@app.delete("/users/sessions/revoke_other")
async def revoke_other(
    user: User = Depends(require_auth),
    authorization: str = Header(...),
    device_id: str = Header(..., alias="X-Device-ID"),
    db: Session = Depends(get_db),
):
    token = authorization.removeprefix("Bearer ").strip()
    current_token_hash = hmac.new(
        SERVER_KEY,
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    (
        db.query(SessionModel)
        .filter(
            SessionModel.user_id == user.id,
            ~(
                (SessionModel.session_token_hash == current_token_hash) &
                (SessionModel.device_id == device_id)
            )
        )
        .delete(synchronize_session=False)
    )

    db.commit()

    return {"status": "other sessions revoked"}

@app.post("/user/pkey/publish", status_code=201)
async def publish_public_key(
    payload: PublishRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    existing = (
        db.query(UserKey)
        .filter(UserKey.user_id == user.id)
        .one_or_none()
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Public key already published",
        )

    user_key = UserKey(
        user_id=user.id,
        identity_pub=payload.identity_pub,
        encrypted_identity_priv=payload.encrypted_identity_priv,
        kdf_salt=payload.kdf_salt,
        aead_nonce=payload.aead_nonce,
    )

    db.add(user_key)
    db.commit()

    return {"status": "published"}

@app.get("/user/pkey/get", response_model=PKeyResponse)
async def get_public_key(
    username: str = Query(...),
    db: Session = Depends(get_db),
):
    user = (
        db.query(User)
        .filter(User.username == username)
        .one_or_none()
    )

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user_key = (
        db.query(UserKey)
        .filter(UserKey.user_id == user.id)
        .one_or_none()
    )

    if not user_key:
        raise HTTPException(
            status_code=404,
            detail="User has not published a public key",
        )

    return {
        "username": user.username,
        "identity_pub": user_key.identity_pub,
    }

# ── WebSocket helper: authenticate from query params ─────────────────

def ws_authenticate(token: str, device_id: str, db: Session) -> User | None:
    """Validate a session token + device-id and return the User, or None."""
    token_hash = hmac.new(
        SERVER_KEY,
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    session = (
        db.query(SessionModel)
        .filter(
            SessionModel.session_token_hash == token_hash,
            SessionModel.expires_at > datetime.now(timezone.utc),
            SessionModel.device_id == device_id,
        )
        .one_or_none()
    )
    if not session:
        return None

    return db.query(User).filter(User.id == session.user_id).one_or_none()


# ── WebSocket endpoint ───────────────────────────────────────────────

@app.websocket("/chat/ws/{chat_id}")
async def chat_ws(
    websocket: WebSocket,
    chat_id: int,
    token: str = Query(...),
    device_id: str = Query(...),
):
    db: Session = SessionLocal()
    try:
        # authenticate
        user = ws_authenticate(token, device_id, db)
        if not user:
            await websocket.close(code=4001, reason="Unauthorized")
            return

        # verify membership
        chat = (
            db.query(Chat)
            .filter(
                Chat.id == chat_id,
                or_(
                    Chat.user_a_id == user.id,
                    Chat.user_b_id == user.id,
                ),
            )
            .one_or_none()
        )
        if not chat:
            await websocket.close(code=4004, reason="Chat not found")
            return

        await manager.connect(chat_id, user.id, websocket)

        # send initial history (last 50 messages)
        messages = (
            db.query(Message)
            .filter(Message.chat_id == chat_id)
            .order_by(desc(Message.id))
            .limit(50)
            .all()
        )
        messages.reverse()

        history_payload = [
            {
                "id": m.id,
                "sender_id": m.sender_id,
                "epoch_id": m.epoch_id,
                "reply_id": m.reply_id,
                "ciphertext": m.ciphertext,
                "nonce": m.nonce,
                "created_at": m.created_at.isoformat(),
            }
            for m in messages
        ]
        next_cursor = messages[0].id if messages else None

        await websocket.send_text(json.dumps({
            "type": "history",
            "messages": history_payload,
            "next_cursor": next_cursor,
        }))

        # keep connection alive – listen for client pings / close
        while True:
            try:
                data = await websocket.receive_text()
                # clients may send {"type":"ping"} to keep alive
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except WebSocketDisconnect:
                break
            except Exception:
                break
    finally:
        manager.disconnect(chat_id, user.id)
        db.close()


# Chat endpoints
@app.get("/chat/list")
async def chat_list(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    
    chats = (
        db.query(Chat)
        .filter(
            or_(
                Chat.user_a_id == user.id,
                Chat.user_b_id == user.id
            )
        )
        .all()
    )

    result = []

    for chat in chats:
        other_user_id = (
            chat.user_b_id if chat.user_a_id == user.id else chat.user_a_id
        )

        other_user = (
            db.query(User)
            .filter(User.id == other_user_id)
            .one()
        )

        result.append({
            "chat_id": chat.id,
            "with_user": other_user.username,
        })

    return result

@app.get("/chat/fetch/{chat_id}")
async def fetch_chat(
    chat_id: int,
    before_id: int | None = Query(None),
    limit: int = Query(50, le=100),
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    chat = (
        db.query(Chat)
        .filter(
            Chat.id == chat_id,
            or_(
                Chat.user_a_id == user.id,
                Chat.user_b_id == user.id,
            ),
        )
        .one_or_none()
    )

    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    query = db.query(Message).filter(Message.chat_id == chat_id)

    if before_id is not None:
        query = query.filter(Message.id < before_id)

    messages = (
        query.order_by(desc(Message.id))
        .limit(limit)
        .all()
    )

    messages.reverse()

    message_payload = [
        {
            "id": m.id,
            "sender_id": m.sender_id,
            "epoch_id": m.epoch_id,
            "reply_id": m.reply_id,
            "ciphertext": m.ciphertext,
            "nonce": m.nonce,
            "created_at": m.created_at,
        }
        for m in messages
    ]

    next_cursor = messages[0].id if messages else None

    return {
        "messages": message_payload,
        "next_cursor": next_cursor,
    }


@app.get("/chat/{chat_id}/{epoch_id}/fetch")
async def fetch_epoch(
    chat_id: int,
    epoch_id: int,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    chat = (
        db.query(Chat)
        .filter(
            Chat.id == chat_id,
            or_(
                Chat.user_a_id == user.id,
                Chat.user_b_id == user.id,
            ),
        )
        .one_or_none()
    )

    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    epoch = (
        db.query(ChatEpoch)
        .filter(
            ChatEpoch.id == epoch_id,
            ChatEpoch.chat_id == chat_id,
        )
        .one_or_none()
    )

    if not epoch:
        raise HTTPException(status_code=404, detail="Epoch not found")

    is_user_a = chat.user_a_id == user.id

    return {
        "epoch_id": epoch.id,
        "epoch_index": epoch.epoch_index,
        "wrapped_key": epoch.wrapped_key_a if is_user_a else epoch.wrapped_key_b,
    }


@app.post("/chat/create")
async def create_chat(
    payload: ChatRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    target = (
        db.query(User)
        .filter(User.username == payload.username)
        .one_or_none()
    )

    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    existing_chat = (
        db.query(Chat)
        .filter(
            or_(
                (Chat.user_a_id == user.id) & (Chat.user_b_id == target.id),
                (Chat.user_a_id == target.id) & (Chat.user_b_id == user.id),
            )
        )
        .one_or_none()
    )

    if existing_chat:
        return {"chat_id": existing_chat.id}

    chat = Chat(user_a_id=user.id, user_b_id=target.id)
    db.add(chat)
    db.flush()

    # create empty epoch 0 placeholder
    epoch0 = ChatEpoch(
        chat_id=chat.id,
        epoch_index=0,
        wrapped_key_a="",
        wrapped_key_b="",
    )
    db.add(epoch0)

    db.commit()

    return {"chat_id": chat.id}

@app.post("/chat/{chat_id}/epoch", status_code=201)
async def create_epoch(
    chat_id: int,
    payload: EpochRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    chat = (
        db.query(Chat)
        .filter(
            Chat.id == chat_id,
            or_(
                Chat.user_a_id == user.id,
                Chat.user_b_id == user.id,
            ),
        )
        .one_or_none()
    )

    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    # rate-limit: at most one epoch every 5 seconds per chat
    # (ignore placeholder epochs with empty keys)
    recent = (
        db.query(ChatEpoch)
        .filter(
            ChatEpoch.chat_id == chat_id,
            ChatEpoch.wrapped_key_a != "",
            ChatEpoch.created_at
            > datetime.now(timezone.utc) - timedelta(seconds=5),
        )
        .count()
    )

    if recent > 0:
        raise HTTPException(status_code=429, detail="Epoch creation throttled")

    # message-count gate (rotate every 200 messages)
    msg_count = (
        db.query(func.count(Message.id))
        .filter(Message.chat_id == chat_id)
        .scalar()
    )

    if msg_count % 200 != 0:
        raise HTTPException(
            status_code=400,
            detail="Epoch rotation not allowed yet",
        )

    # serialize epoch creation
    last_epoch = (
        db.query(ChatEpoch)
        .filter(ChatEpoch.chat_id == chat_id)
        .order_by(ChatEpoch.epoch_index.desc())
        .with_for_update()
        .first()
    )

    next_index = 0 if not last_epoch else last_epoch.epoch_index + 1

    epoch = ChatEpoch(
        chat_id=chat_id,
        epoch_index=next_index,
        wrapped_key_a=payload.wrapped_key_a,
        wrapped_key_b=payload.wrapped_key_b,
    )

    db.add(epoch)
    db.commit()
    db.refresh(epoch)

    return {
        "epoch_id": epoch.id,
        "epoch_index": epoch.epoch_index,
    }

@app.post("/chat/{chat_id}/message", status_code=201)
async def message(
    chat_id: int,
    payload: MessageRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    chat = (
        db.query(Chat)
        .filter(
            Chat.id == chat_id,
            or_(
                Chat.user_a_id == user.id,
                Chat.user_b_id == user.id,
            ),
        )
        .one_or_none()
    )

    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    epoch = (
        db.query(ChatEpoch)
        .filter(
            ChatEpoch.id == payload.epoch_id,
            ChatEpoch.chat_id == chat_id,
        )
        .one_or_none()
    )

    if not epoch:
        raise HTTPException(status_code=409, detail="Unknown epoch")

    latest_epoch = (
        db.query(ChatEpoch)
        .filter(ChatEpoch.chat_id == chat_id)
        .order_by(ChatEpoch.epoch_index.desc())
        .first()
    )

    if epoch.id != latest_epoch.id:
        raise HTTPException(
            status_code=409,
            detail="Stale epoch; fetch latest epoch",
        )

    if not epoch.wrapped_key_a or not epoch.wrapped_key_b:
        raise HTTPException(
            status_code=409,
            detail="Epoch not initialized",
        )

    msg = Message(
        chat_id=chat.id,
        sender_id=user.id,
        epoch_id=payload.epoch_id,
        reply_id=payload.reply_id,
        ciphertext=payload.ciphertext,
        nonce=payload.nonce,
    )

    db.add(msg)
    db.commit()
    db.refresh(msg)

    # broadcast to WebSocket subscribers of this chat
    ws_payload = {
        "type": "new_message",
        "message": {
            "id": msg.id,
            "sender_id": msg.sender_id,
            "epoch_id": msg.epoch_id,
            "reply_id": msg.reply_id,
            "ciphertext": msg.ciphertext,
            "nonce": msg.nonce,
            "created_at": msg.created_at.isoformat(),
        },
    }
    asyncio.ensure_future(manager.broadcast(chat_id, ws_payload))

    return {
        "id": msg.id,
        "epoch_id": msg.epoch_id,
        "created_at": msg.created_at,
    }
