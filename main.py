import asyncio
import hashlib
import hmac
import importlib
import json
import logging
import uuid
import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Header, Depends, WebSocket, WebSocketDisconnect, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, desc, case
from argon2 import PasswordHasher
from models import Session as SessionModel
from argon2.exceptions import VerifyMismatchError
from datetime import datetime, timedelta, timezone
from schema import AuthRequest, ChatRequest, MessageRequest, PublishRequest, PKeyResponse, SignupRequest, EpochRequest, RegisterFcmTokenRequest, DeviceFcmTokenResponse
import secrets

from models import init_db, SessionLocal, User, Chat, Message, UserKey, ChatEpoch, Media, MessageMedia, UPLOAD_DIR, DevicePushToken

MAX_CHUNK_SIZE = 256 * 1024 * 1024  # 256 MiB
FCM_PLATFORM_ANDROID = "android"

app = FastAPI()

load_dotenv()

app.mount("/site", StaticFiles(directory="static", html=True), name="site-static")
app.mount("/app", StaticFiles(directory="static", html=True), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ph = PasswordHasher()
# Use uvicorn's logger so startup push status is visible with --log-level info.
logger = logging.getLogger("uvicorn.error")

# ── WebSocket connection manager ──────────────────────────────────────

class ConnectionManager:
    """Tracks active WebSocket connections per chat."""

    def __init__(self):
        # chat_id -> dict[user_id, dict[device_id, WebSocket]]
        self.active: dict[int, dict[int, dict[str, WebSocket]]] = {}

    async def connect(self, chat_id: int, user_id: int, device_id: str, ws: WebSocket):
        self.active.setdefault(chat_id, {}).setdefault(user_id, {})[device_id] = ws

    def disconnect(self, chat_id: int, user_id: int, device_id: str):
        chat_conns = self.active.get(chat_id)
        if chat_conns:
            user_conns = chat_conns.get(user_id)
            if user_conns:
                user_conns.pop(device_id, None)
                if not user_conns:
                    chat_conns.pop(user_id, None)
            if not chat_conns:
                del self.active[chat_id]

    async def broadcast(self, chat_id: int, payload: dict, exclude_user_id: int | None = None):
        """Send a JSON message to every user connected to *chat_id*."""
        chat_conns = self.active.get(chat_id)
        if not chat_conns:
            return
        data = json.dumps(payload)
        stale: list[tuple[int, str]] = []
        for uid, device_conns in chat_conns.items():
            if uid == exclude_user_id:
                continue
            for device_id, ws in device_conns.items():
                try:
                    await ws.send_text(data)
                except Exception:
                    stale.append((uid, device_id))
        for uid, device_id in stale:
            self.disconnect(chat_id, uid, device_id)

    def active_device_ids(self, chat_id: int, user_id: int) -> set[str]:
        chat_conns = self.active.get(chat_id, {})
        return set(chat_conns.get(user_id, {}).keys())

manager = ConnectionManager()


class FcmNotifier:
    def __init__(self):
        self.enabled = False
        self.firebase_admin = None
        self.credentials = None
        self.messaging = None

    def initialize(self):
        try:
            self.firebase_admin = importlib.import_module("firebase_admin")
            self.credentials = importlib.import_module("firebase_admin.credentials")
            self.messaging = importlib.import_module("firebase_admin.messaging")
        except Exception:
            logger.warning("Firebase Admin SDK not available; push notifications are disabled")
            return

        credentials_path = os.environ.get("FIREBASE_CREDENTIALS_PATH")
        if not credentials_path:
            logger.warning("FIREBASE_CREDENTIALS_PATH not set; push notifications are disabled")
            return

        if not os.path.exists(credentials_path):
            logger.warning("Firebase credentials file not found at configured path")
            return

        try:
            if not self.firebase_admin._apps:
                cred = self.credentials.Certificate(credentials_path)
                self.firebase_admin.initialize_app(cred)
            self.enabled = True
            logger.info("Firebase push notifications enabled")
        except Exception as exc:
            logger.warning("Failed to initialize Firebase Admin SDK: %s", exc)

    @staticmethod
    def _is_invalid_token_error(exc: Exception) -> bool:
        value = str(exc).lower()
        return (
            "unregistered" in value
            or "registration-token-not-registered" in value
            or "invalid registration token" in value
            or "invalid argument" in value
        )

    @staticmethod
    def _mask_token(token: str) -> str:
        if len(token) <= 12:
            return "***"
        return f"{token[:6]}...{token[-6:]}"

    async def send_wake(
        self,
        fcm_tokens: list[str],
        sender_id: int,
        chat_id: int,
        created_at: str,
    ) -> dict[str, set[str]]:
        result = {
            "ok": set(),
            "failed": set(),
            "invalid": set(),
        }
        if not self.enabled or self.messaging is None:
            logger.info(
                "FCM wake skipped: notifier disabled or Firebase messaging unavailable (chat_id=%s sender_id=%s tokens=%s)",
                chat_id,
                sender_id,
                len(fcm_tokens),
            )
            return result

        data_payload = {
            "event": "chat_wake",
            "chat_id": str(chat_id),
            "sender_id": str(sender_id),
            "created_at": created_at,
            "body": "New message",
        }

        def _send_all() -> dict[str, set[str]]:
            local_result = {
                "ok": set(),
                "failed": set(),
                "invalid": set(),
            }

            logger.info(
                "FCM wake dispatch started (chat_id=%s sender_id=%s tokens=%s)",
                chat_id,
                sender_id,
                len(fcm_tokens),
            )
            for token in fcm_tokens:
                msg = self.messaging.Message(
                    token=token,
                    data=data_payload,
                    android=self.messaging.AndroidConfig(priority="high"),
                )
                try:
                    fcm_message_id = self.messaging.send(msg)
                    local_result["ok"].add(token)
                    logger.info(
                        "FCM wake sent (chat_id=%s sender_id=%s token=%s message_id=%s)",
                        chat_id,
                        sender_id,
                        self._mask_token(token),
                        fcm_message_id,
                    )
                except Exception as exc:
                    if self._is_invalid_token_error(exc):
                        local_result["invalid"].add(token)
                        logger.warning(
                            "FCM wake invalid token (chat_id=%s sender_id=%s token=%s error=%s)",
                            chat_id,
                            sender_id,
                            self._mask_token(token),
                            exc,
                        )
                    else:
                        local_result["failed"].add(token)
                        logger.error(
                            "FCM wake send failed (chat_id=%s sender_id=%s token=%s error=%s)",
                            chat_id,
                            sender_id,
                            self._mask_token(token),
                            exc,
                        )

            logger.info(
                "FCM wake dispatch completed (chat_id=%s sender_id=%s ok=%s failed=%s invalid=%s)",
                chat_id,
                sender_id,
                len(local_result["ok"]),
                len(local_result["failed"]),
                len(local_result["invalid"]),
            )
            return local_result

        return await asyncio.to_thread(_send_all)


fcm_notifier = FcmNotifier()


async def notify_chat_wake(
    chat_id: int,
    recipient_user_id: int,
    sender_id: int,
    created_at: datetime,
):
    if not fcm_notifier.enabled:
        logger.info(
            "FCM wake not attempted: notifier disabled (chat_id=%s sender_id=%s recipient_user_id=%s)",
            chat_id,
            sender_id,
            recipient_user_id,
        )
        return

    db: Session = SessionLocal()
    try:
        excluded_device_ids = manager.active_device_ids(chat_id, recipient_user_id)
        tokens_query = (
            db.query(DevicePushToken)
            .filter(
                DevicePushToken.user_id == recipient_user_id,
                DevicePushToken.platform == FCM_PLATFORM_ANDROID,
                DevicePushToken.enabled == True,
            )
        )

        if excluded_device_ids:
            tokens_query = tokens_query.filter(~DevicePushToken.device_id.in_(excluded_device_ids))

        token_rows = tokens_query.all()
        if not token_rows:
            logger.info(
                "FCM wake skipped: no eligible recipient tokens (chat_id=%s sender_id=%s recipient_user_id=%s excluded_devices=%s)",
                chat_id,
                sender_id,
                recipient_user_id,
                len(excluded_device_ids),
            )
            return

        fcm_tokens = [row.fcm_token for row in token_rows]
    finally:
        db.close()

    push_result = await fcm_notifier.send_wake(
        fcm_tokens=fcm_tokens,
        sender_id=sender_id,
        chat_id=chat_id,
        created_at=created_at.isoformat(),
    )

    logger.info(
        "FCM wake result (chat_id=%s sender_id=%s recipient_user_id=%s attempted=%s ok=%s failed=%s invalid=%s)",
        chat_id,
        sender_id,
        recipient_user_id,
        len(fcm_tokens),
        len(push_result["ok"]),
        len(push_result["failed"]),
        len(push_result["invalid"]),
    )

    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        rows = (
            db.query(DevicePushToken)
            .filter(DevicePushToken.fcm_token.in_(fcm_tokens))
            .all()
        )
        for row in rows:
            if row.fcm_token in push_result["invalid"]:
                row.enabled = False
                row.invalid_since = now
                row.failure_count += 1
                row.last_error = "invalid-token"
            elif row.fcm_token in push_result["failed"]:
                row.failure_count += 1
                row.last_error = "send-failed"
            elif row.fcm_token in push_result["ok"]:
                row.last_success_at = now
                row.last_error = None
                row.failure_count = 0

        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

# ── Startup ───────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_db()
    fcm_notifier.initialize()

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

@app.get("/site")
async def site_root():
    return RedirectResponse(url="/site/")

@app.get("/version")
async def get_version():
    return {"version": "60"}

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
    authorization: str = Header(...),
    device_Id: str = Header(..., alias="X-Device-ID"),
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    token = authorization.removeprefix("Bearer ").strip()
    token_hash = hmac.new(
        SERVER_KEY,
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    session = (
        db.query(SessionModel)
        .filter(
            SessionModel.session_token_hash == token_hash,
            SessionModel.user_id == user.id,
            SessionModel.device_id == device_Id,
        )
        .one_or_none()
    )

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    now = datetime.now(timezone.utc)
    (
        db.query(DevicePushToken)
        .filter(
            DevicePushToken.user_id == user.id,
            DevicePushToken.device_id == device_Id,
            DevicePushToken.enabled == True,
        )
        .update(
            {
                DevicePushToken.enabled: False,
                DevicePushToken.invalid_since: now,
                DevicePushToken.last_error: "logged-out",
            },
            synchronize_session=False,
        )
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


@app.post("/device/fcm/register", response_model=DeviceFcmTokenResponse)
async def register_device_fcm_token(
    payload: RegisterFcmTokenRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
    device_id: str = Header(..., alias="X-Device-ID"),
):
    platform = payload.platform.lower().strip()
    if platform != FCM_PLATFORM_ANDROID:
        raise HTTPException(status_code=400, detail="Only android is supported")

    token_value = payload.fcm_token.strip()
    if not token_value:
        raise HTTPException(status_code=400, detail="fcm_token is required")

    row = (
        db.query(DevicePushToken)
        .filter(
            DevicePushToken.user_id == user.id,
            DevicePushToken.device_id == device_id,
            DevicePushToken.platform == platform,
        )
        .one_or_none()
    )

    if not row:
        row = (
            db.query(DevicePushToken)
            .filter(DevicePushToken.fcm_token == token_value)
            .one_or_none()
        )

    if not row:
        row = DevicePushToken(
            user_id=user.id,
            device_id=device_id,
            platform=platform,
            fcm_token=token_value,
            enabled=True,
            failure_count=0,
        )
        db.add(row)
    else:
        row.user_id = user.id
        row.device_id = device_id
        row.platform = platform
        row.fcm_token = token_value
        row.enabled = True
        row.failure_count = 0
        row.last_error = None
        row.invalid_since = None

    db.commit()
    db.refresh(row)

    return {
        "id": row.id,
        "device_id": row.device_id,
        "platform": row.platform,
        "enabled": row.enabled,
        "failure_count": row.failure_count,
        "invalid_since": row.invalid_since.isoformat() if row.invalid_since else None,
    }


@app.delete("/device/fcm/current")
async def disable_current_device_fcm_token(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
    device_id: str = Header(..., alias="X-Device-ID"),
):
    now = datetime.now(timezone.utc)
    updated = (
        db.query(DevicePushToken)
        .filter(
            DevicePushToken.user_id == user.id,
            DevicePushToken.device_id == device_id,
            DevicePushToken.platform == FCM_PLATFORM_ANDROID,
            DevicePushToken.enabled == True,
        )
        .update(
            {
                DevicePushToken.enabled: False,
                DevicePushToken.invalid_since: now,
                DevicePushToken.last_error: "disabled-by-user",
            },
            synchronize_session=False,
        )
    )

    db.commit()
    return {"status": "disabled", "updated": updated}


@app.get("/device/fcm/tokens", response_model=list[DeviceFcmTokenResponse])
async def list_device_fcm_tokens(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(DevicePushToken)
        .filter(
            DevicePushToken.user_id == user.id,
            DevicePushToken.platform == FCM_PLATFORM_ANDROID,
        )
        .order_by(desc(DevicePushToken.updated_at))
        .all()
    )
    return [
        {
            "id": row.id,
            "device_id": row.device_id,
            "platform": row.platform,
            "enabled": row.enabled,
            "failure_count": row.failure_count,
            "invalid_since": row.invalid_since.isoformat() if row.invalid_since else None,
        }
        for row in rows
    ]


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

# ── Media endpoints ───────────────────────────────────────────────────

@app.post("/media/upload", status_code=201)
async def upload_media(
    file: UploadFile = File(...),
    chat_id: int = Form(...),
    mime_type: str = Form(...),
    nonce: str = Form(...),
    chunk_index: int = Form(0),
    total_chunks: int = Form(1),
    upload_id: str = Form(...),
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    # verify chat membership
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

    #validate upload_id
    if not uuid.UUID(upload_id, version=4):
        raise HTTPException(status_code=400, detail="Invalid upload_id")

    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    # validate chunk parameters
    if chunk_index < 0 or chunk_index >= total_chunks:
        raise HTTPException(status_code=400, detail="Invalid chunk_index")

    if total_chunks < 1:
        raise HTTPException(status_code=400, detail="total_chunks must be >= 1")

    # read file content and enforce 256 MiB chunk limit
    content = await file.read()
    file_size = len(content)

    if file_size > MAX_CHUNK_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Chunk exceeds maximum size of 256 MiB ({MAX_CHUNK_SIZE} bytes)",
        )

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    # check for duplicate chunk
    existing_chunk = (
        db.query(Media)
        .filter(
            Media.upload_id == upload_id,
            Media.chunk_index == chunk_index,
        )
        .one_or_none()
    )

    if existing_chunk:
        raise HTTPException(status_code=409, detail="Chunk already uploaded")

    # store on disk: uploads/<chat_id>/<upload_id>_<chunk_index>
    chat_dir = os.path.join(UPLOAD_DIR, str(chat_id))
    os.makedirs(chat_dir, exist_ok=True)

    filename = f"{upload_id}_{chunk_index}"
    disk_path = os.path.join(chat_dir, filename)

    with open(disk_path, "wb") as f:
        f.write(content)

    media = Media(
        uploader_id=user.id,
        chat_id=chat_id,
        mime_type=mime_type,
        file_path=disk_path,
        file_size=file_size,
        nonce=nonce,
        chunk_index=chunk_index,
        total_chunks=total_chunks,
        upload_id=upload_id,
    )

    db.add(media)
    db.commit()
    db.refresh(media)

    # check overall upload completeness
    uploaded_count = (
        db.query(func.count(Media.id))
        .filter(Media.upload_id == upload_id)
        .scalar()
    )

    return {
        "media_id": media.id,
        "upload_id": upload_id,
        "chunk_index": chunk_index,
        "chunks_uploaded": uploaded_count,
        "total_chunks": total_chunks,
        "complete": uploaded_count == total_chunks,
    }


@app.get("/media/{media_id}/meta")
async def get_media_meta(
    media_id: int,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    media = db.query(Media).filter(Media.id == media_id).one_or_none()

    if not media:
        raise HTTPException(status_code=404, detail="Media not found")

    # verify chat membership
    chat = (
        db.query(Chat)
        .filter(
            Chat.id == media.chat_id,
            or_(
                Chat.user_a_id == user.id,
                Chat.user_b_id == user.id,
            ),
        )
        .one_or_none()
    )

    if not chat:
        raise HTTPException(status_code=404, detail="Media not found")

    # return all chunks for this upload
    chunks = (
        db.query(Media)
        .filter(Media.upload_id == media.upload_id)
        .order_by(Media.chunk_index)
        .all()
    )

    return {
        "upload_id": media.upload_id,
        "mime_type": media.mime_type,
        "total_chunks": media.total_chunks,
        "nonce": media.nonce,
        "chunks": [
            {
                "media_id": c.id,
                "chunk_index": c.chunk_index,
                "file_size": c.file_size,
            }
            for c in chunks
        ],
    }


@app.get("/media/download/{media_id}")
async def download_media(
    media_id: int,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    media = db.query(Media).filter(Media.id == media_id).one_or_none()

    if not media:
        raise HTTPException(status_code=404, detail="Media not found")

    # verify chat membership
    chat = (
        db.query(Chat)
        .filter(
            Chat.id == media.chat_id,
            or_(
                Chat.user_a_id == user.id,
                Chat.user_b_id == user.id,
            ),
        )
        .one_or_none()
    )

    if not chat:
        raise HTTPException(status_code=404, detail="Media not found")

    if not os.path.exists(media.file_path):
        raise HTTPException(status_code=404, detail="File not found on disk")

    return FileResponse(
        path=media.file_path,
        media_type="application/octet-stream",
        filename=f"{media.upload_id}_{media.chunk_index}",
    )


def _attachments_for_message(message_id: int, db: Session) -> list[dict]:
    """Return media attachment metadata for a message."""
    rows = (
        db.query(MessageMedia, Media)
        .join(Media, MessageMedia.media_id == Media.id)
        .filter(MessageMedia.message_id == message_id)
        .all()
    )

    # group by upload_id
    uploads: dict[str, list] = {}
    for _mm, m in rows:
        uploads.setdefault(m.upload_id, []).append(m)

    result = []
    for upload_id, chunks in uploads.items():
        chunks.sort(key=lambda c: c.chunk_index)
        first = chunks[0]
        result.append({
            "upload_id": upload_id,
            "mime_type": first.mime_type,
            "nonce": first.nonce,
            "total_chunks": first.total_chunks,
            "total_size": sum(c.file_size for c in chunks),
            "chunks": [
                {
                    "media_id": c.id,
                    "chunk_index": c.chunk_index,
                    "file_size": c.file_size,
                }
                for c in chunks
            ],
        })

    return result


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
):
    await websocket.accept()
    db: Session = SessionLocal()
    user = None
    ws_device_id: str | None = None
    try:
        # wait for the first frame which must be an auth message
        try:
            raw = await asyncio.wait_for(websocket.receive_text(), timeout=10)
            auth_msg = json.loads(raw)
        except (asyncio.TimeoutError, Exception):
            await websocket.close(code=4001, reason="Unauthorized")
            return

        if auth_msg.get("type") != "auth":
            await websocket.close(code=4001, reason="Unauthorized")
            return

        token = auth_msg.get("token", "")
        device_id = auth_msg.get("device_id", "")
        ws_device_id = device_id

        # authenticate
        user = ws_authenticate(token, device_id, db)
        token = None  # discard credential
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

        self_conns = manager.active.get(chat_id, {})
        if device_id in self_conns.get(user.id, {}):
            await websocket.close(code=4001, reason="Unauthorized")
            return

        await manager.connect(chat_id, user.id, device_id, websocket)

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
                "attachments": _attachments_for_message(m.id, db),
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
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except WebSocketDisconnect:
                break
            except Exception:
                break
    finally:
        if user and ws_device_id:
            manager.disconnect(chat_id, user.id, ws_device_id)
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
            "attachments": _attachments_for_message(m.id, db),
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
    db.flush()

    # link media attachments
    if payload.media_ids:
        for mid in payload.media_ids:
            media = (
                db.query(Media)
                .filter(
                    Media.id == mid,
                    Media.chat_id == chat_id,
                )
                .one_or_none()
            )

            if not media:
                db.rollback()
                raise HTTPException(
                    status_code=400,
                    detail=f"Media {mid} not found or does not belong to this chat",
                )

            # ensure all chunks are uploaded
            uploaded = (
                db.query(func.count(Media.id))
                .filter(Media.upload_id == media.upload_id)
                .scalar()
            )

            if uploaded < media.total_chunks:
                db.rollback()
                raise HTTPException(
                    status_code=400,
                    detail=f"Upload {media.upload_id} is incomplete ({uploaded}/{media.total_chunks} chunks)",
                )

            # link all chunks of this upload to the message
            upload_chunks = (
                db.query(Media)
                .filter(Media.upload_id == media.upload_id)
                .all()
            )
            for chunk in upload_chunks:
                existing_link = (
                    db.query(MessageMedia)
                    .filter(
                        MessageMedia.message_id == msg.id,
                        MessageMedia.media_id == chunk.id,
                    )
                    .one_or_none()
                )
                if not existing_link:
                    db.add(MessageMedia(message_id=msg.id, media_id=chunk.id))

    db.commit()
    db.refresh(msg)

    attachments = _attachments_for_message(msg.id, db)

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
            "attachments": attachments,
        },
    }
    asyncio.ensure_future(manager.broadcast(chat_id, ws_payload))
    recipient_user_id = chat.user_b_id if chat.user_a_id == user.id else chat.user_a_id
    asyncio.ensure_future(
        notify_chat_wake(
            chat_id=chat_id,
            recipient_user_id=recipient_user_id,
            sender_id=user.id,
            created_at=msg.created_at,
        )
    )

    return {
        "id": msg.id,
        "epoch_id": msg.epoch_id,
        "created_at": msg.created_at,
        "attachments": attachments,
    }
