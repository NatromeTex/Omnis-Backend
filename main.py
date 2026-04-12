import asyncio
import hashlib
import hmac
import importlib
import json
import logging
import re
import uuid
import os
from collections import deque
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Header, Depends, WebSocket, WebSocketDisconnect, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, desc, case
from argon2 import PasswordHasher
from models import Session as SessionModel
from argon2.exceptions import VerifyMismatchError
from datetime import datetime, timedelta, timezone
from schema import AuthRequest, ChatRequest, MessageRequest, PublishRequest, PKeyResponse, SignupRequest, EpochRequest, RegisterFcmTokenRequest, DeviceFcmTokenResponse, CallInitiateResponse, CallHistoryResponse
import secrets
import rjsmin

from models import init_db, SessionLocal, User, Chat, Message, UserKey, ChatEpoch, Media, MessageMedia, UPLOAD_DIR, DevicePushToken, CallRecord, CallStatus

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

_MEDIA_UPLOAD_MAX_BODY = 256 * 1024 * 1024  # 256 MiB — matches chunk limit
_DEFAULT_MAX_BODY = 1 * 1024 * 1024          # 1 MiB for all other endpoints

@app.middleware("http")
async def limit_request_body(request: Request, call_next):
    limit = _MEDIA_UPLOAD_MAX_BODY if request.url.path == "/media/upload" else _DEFAULT_MAX_BODY
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > limit:
                from fastapi.responses import JSONResponse
                return JSONResponse({"detail": "Request body too large"}, status_code=413)
        except ValueError:
            pass
    return await call_next(request)

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


def _as_utc(dt) -> datetime | None:
    """Ensure a datetime is timezone-aware (UTC). SQLite returns naive datetimes."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class CallManager:
    """Tracks active WebSocket connections for in-progress calls.
    Structure: call_uuid -> user_id -> WebSocket (at most 2 users per call).
    """

    def __init__(self):
        self.active: dict[str, dict[int, WebSocket]] = {}
        self._timeouts: dict[str, asyncio.TimerHandle] = {}
        self._disconnect_tasks: dict[str, dict[int, asyncio.Task]] = {}

    async def connect(self, call_uuid: str, user_id: int, ws: WebSocket) -> None:
        self.active.setdefault(call_uuid, {})[user_id] = ws

    def disconnect(self, call_uuid: str, user_id: int) -> None:
        call_conns = self.active.get(call_uuid)
        if call_conns:
            call_conns.pop(user_id, None)
            if not call_conns:
                del self.active[call_uuid]

    async def send_to(self, call_uuid: str, user_id: int, payload: dict) -> bool:
        """Send to one specific participant. Returns False if not connected."""
        ws = self.active.get(call_uuid, {}).get(user_id)
        if not ws:
            return False
        try:
            await ws.send_text(json.dumps(payload))
            return True
        except Exception:
            self.disconnect(call_uuid, user_id)
            return False

    async def broadcast(self, call_uuid: str, payload: dict,
                        exclude_user_id: int | None = None) -> None:
        """Relay a message to all participants of a call."""
        conns = self.active.get(call_uuid, {})
        data = json.dumps(payload)
        stale: list[int] = []
        for uid, ws in conns.items():
            if uid == exclude_user_id:
                continue
            try:
                await ws.send_text(data)
            except Exception:
                stale.append(uid)
        for uid in stale:
            self.disconnect(call_uuid, uid)

    def is_participant_connected(self, call_uuid: str, user_id: int) -> bool:
        return user_id in self.active.get(call_uuid, {})

    def schedule_missed_timeout(self, call_uuid: str, callback, delay: float = 30.0) -> None:
        """Schedule a missed-call callback after `delay` seconds."""
        loop = asyncio.get_event_loop()
        handle = loop.call_later(delay, callback)
        self._timeouts[call_uuid] = handle

    def cancel_timeout(self, call_uuid: str) -> None:
        handle = self._timeouts.pop(call_uuid, None)
        if handle:
            handle.cancel()

    def schedule_disconnect_finalize(
        self, call_uuid: str, user_id: int, coro
    ) -> None:
        """Start a grace-period task that finalizes the call unless the user reconnects."""
        task = asyncio.ensure_future(coro)
        self._disconnect_tasks.setdefault(call_uuid, {})[user_id] = task

    def cancel_disconnect_task(self, call_uuid: str, user_id: int) -> bool:
        """Cancel a pending disconnect finalization. Returns True if one was cancelled."""
        tasks = self._disconnect_tasks.get(call_uuid, {})
        task = tasks.pop(user_id, None)
        if not tasks:
            self._disconnect_tasks.pop(call_uuid, None)
        if task:
            task.cancel()
            return True
        return False

    def has_disconnect_task(self, call_uuid: str, user_id: int) -> bool:
        return user_id in self._disconnect_tasks.get(call_uuid, {})


call_manager = CallManager()


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

    async def send_call_event(
        self,
        fcm_tokens: list[str],
        event_type: str,
        call_uuid: str,
        chat_id: int,
        caller_id: int,
    ) -> dict[str, set[str]]:
        result: dict[str, set[str]] = {"ok": set(), "failed": set(), "invalid": set()}
        if not self.enabled or self.messaging is None:
            return result

        data_payload = {
            "event": event_type,
            "call_id": call_uuid,
            "chat_id": str(chat_id),
            "caller_id": str(caller_id),
        }

        def _send_all() -> dict[str, set[str]]:
            local: dict[str, set[str]] = {"ok": set(), "failed": set(), "invalid": set()}
            for token in fcm_tokens:
                msg = self.messaging.Message(
                    token=token,
                    data=data_payload,
                    android=self.messaging.AndroidConfig(priority="high"),
                )
                try:
                    self.messaging.send(msg)
                    local["ok"].add(token)
                    logger.info(
                        "FCM call event sent (event=%s call_id=%s token=%s)",
                        event_type, call_uuid, self._mask_token(token),
                    )
                except Exception as exc:
                    if self._is_invalid_token_error(exc):
                        local["invalid"].add(token)
                        logger.warning(
                            "FCM call event invalid token (event=%s call_id=%s token=%s error=%s)",
                            event_type, call_uuid, self._mask_token(token), exc,
                        )
                    else:
                        local["failed"].add(token)
                        logger.error(
                            "FCM call event send failed (event=%s call_id=%s token=%s error=%s)",
                            event_type, call_uuid, self._mask_token(token), exc,
                        )
            return local

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

        now = datetime.now(timezone.utc)
        for row in token_rows:
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

async def notify_call_event(
    call_uuid: str,
    chat_id: int,
    recipient_user_id: int,
    caller_id: int,
    event_type: str,
    exclude_device_ids: set[str] | None = None,
) -> None:
    """Send a call FCM push to recipient's eligible devices.

    Mirrors notify_chat_wake. Pass exclude_device_ids to skip devices that
    were already notified via the chat WebSocket broadcast.
    """
    if not fcm_notifier.enabled:
        return

    db: Session = SessionLocal()
    try:
        q = (
            db.query(DevicePushToken)
            .filter(
                DevicePushToken.user_id == recipient_user_id,
                DevicePushToken.platform == FCM_PLATFORM_ANDROID,
                DevicePushToken.enabled == True,
            )
        )
        if exclude_device_ids:
            q = q.filter(~DevicePushToken.device_id.in_(exclude_device_ids))

        token_rows = q.all()
        if not token_rows:
            return

        push_result = await fcm_notifier.send_call_event(
            fcm_tokens=[r.fcm_token for r in token_rows],
            event_type=event_type,
            call_uuid=call_uuid,
            chat_id=chat_id,
            caller_id=caller_id,
        )

        now = datetime.now(timezone.utc)
        for row in token_rows:
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


def _finalize_call(db: Session, call: CallRecord, status: CallStatus) -> Message:
    """Write a terminal call status to DB and insert a call system message.

    Returns the inserted Message so callers can broadcast it to the chat WS.
    """
    call.status = status
    call.ended_at = datetime.now(timezone.utc)
    db.flush()  # set ended_at before computing duration

    duration: int | None = None
    if call.answered_at and call.ended_at:
        duration = int((_as_utc(call.ended_at) - _as_utc(call.answered_at)).total_seconds())

    call_msg = Message(
        chat_id=call.chat_id,
        sender_id=call.initiator_id,
        message_type="call",
        call_uuid=call.call_uuid,
        call_status=status,
        duration_seconds=duration,
        epoch_id=None,
        ciphertext="",
        nonce="",
    )
    db.add(call_msg)
    db.commit()
    db.refresh(call_msg)
    return call_msg


def _call_chat_ws_payload(call_msg: Message) -> dict:
    """Build the new_message WS payload for a call system message."""
    return {
        "type": "new_message",
        "message": {
            "id": call_msg.id,
            "sender_id": call_msg.sender_id,
            "message_type": call_msg.message_type,
            "call_uuid": call_msg.call_uuid,
            "call_status": call_msg.call_status,
            "duration_seconds": call_msg.duration_seconds,
            "epoch_id": None,
            "reply_id": None,
            "ciphertext": None,
            "nonce": None,
            "deleted": False,
            "created_at": call_msg.created_at.isoformat(),
            "attachments": [],
        },
    }


async def _handle_missed_call(
    call_uuid: str,
    chat_id: int,
    initiator_id: int,
    recipient_id: int,
) -> None:
    """Fires after the missed-call timeout — marks call missed if still pre-accepted."""
    db: Session = SessionLocal()
    try:
        call = (
            db.query(CallRecord)
            .filter(CallRecord.call_uuid == call_uuid)
            .one_or_none()
        )
        if not call or call.status not in (CallStatus.initiated, CallStatus.ringing):
            return
        call_msg = _finalize_call(db, call, CallStatus.missed)
        await call_manager.broadcast(call_uuid, {
            "type": "call_state",
            "status": CallStatus.missed,
            "call_id": call_uuid,
        })
        await manager.broadcast(chat_id, _call_chat_ws_payload(call_msg))
        await notify_call_event(
            call_uuid=call_uuid,
            chat_id=chat_id,
            recipient_user_id=recipient_id,
            caller_id=initiator_id,
            event_type="call_missed",
        )
    except Exception:
        db.rollback()
    finally:
        db.close()


async def _disconnect_finalize_after_delay(
    call_uuid: str,
    user_id: int,
    other_id: int,
    delay: float = 10.0,
) -> None:
    """Grace-period task: finalize the call if the disconnected user doesn't reconnect."""
    try:
        await asyncio.sleep(delay)
    except asyncio.CancelledError:
        return  # User reconnected — task was cancelled

    db: Session = SessionLocal()
    try:
        call = (
            db.query(CallRecord)
            .filter(CallRecord.call_uuid == call_uuid)
            .one_or_none()
        )
        if not call or call.status in (CallStatus.ended, CallStatus.rejected, CallStatus.missed):
            return
        call_msg = _finalize_call(db, call, CallStatus.ended)
        call_manager.cancel_timeout(call_uuid)
        await call_manager.broadcast(call_uuid, {"type": "ended", "call_id": call_uuid})
        await manager.broadcast(call.chat_id, _call_chat_ws_payload(call_msg))
        await notify_call_event(
            call_uuid=call_uuid,
            chat_id=call.chat_id,
            recipient_user_id=other_id,
            caller_id=user_id,
            event_type="call_ended",
        )
    except Exception:
        db.rollback()
    finally:
        # Remove task reference
        tasks = call_manager._disconnect_tasks.get(call_uuid, {})
        tasks.pop(user_id, None)
        if not tasks:
            call_manager._disconnect_tasks.pop(call_uuid, None)
        db.close()


# ── Startup ───────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_db()
    fcm_notifier.initialize()
    _minify_js()


def _minify_js():
    src = os.path.join("static", "app.js")
    dst = os.path.join("static", "app.min.js")
    with open(src) as f:
        minified = rjsmin.jsmin(f.read())
    with open(dst, "w") as f:
        f.write(minified)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

_raw_key = os.environ.get("SERVER_KEY", "")
if not _raw_key:
    raise RuntimeError("SERVER_KEY environment variable is not set")
SERVER_KEY = _raw_key.encode()
if len(SERVER_KEY) < 10:
    raise RuntimeError("SERVER_KEY must be at least 10 characters")

def is_valid_uuid4(value: str) -> bool:
    """Return True iff value is a canonical lowercase UUID v4 string."""
    try:
        val = uuid.UUID(value, version=4)
        return str(val) == value.lower()
    except (ValueError, AttributeError):
        return False

_NONCE_RE = re.compile(r'^[A-Za-z0-9+/=_-]{16,48}$')

def is_valid_nonce(value: str) -> bool:
    """Return True iff value looks like a valid AES-GCM nonce (base64/hex, 16-48 chars)."""
    return bool(_NONCE_RE.match(value))

# ── Login rate-limiting state ─────────────────────────────────────────
# Maps IP -> list of failed-attempt datetimes (cleared on ban)
_login_attempts: dict[str, list] = {}
# Maps IP -> ban-expiry datetime
_ip_bans: dict[str, datetime] = {}

async def require_auth(
    authorization: str = Header(...),
    db: Session = Depends(get_db),
    device_Id: str = Header(..., alias="X-Device-ID")
) -> User:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    if not is_valid_uuid4(device_Id):
        raise HTTPException(status_code=401, detail="Invalid device ID")

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

    session.last_accessed = datetime.now(timezone.utc)
    db.commit()

    return user

@app.get("/")
async def read_root():
    return {"ping": "pong"}

@app.get("/site")
async def site_root():
    return RedirectResponse(url="/site/")

@app.get("/version")
async def get_version():
    return {"version": "75"}

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
    request: Request,
    payload: AuthRequest,
    db: Session = Depends(get_db),
    device_Id: str = Header(..., alias="X-Device-ID"),
    user_Agent: str | None = Header(None),
):
    client_ip = request.client.host if request.client else "unknown"

    # Check IP ban
    ban_expiry = _ip_bans.get(client_ip)
    if ban_expiry and ban_expiry > datetime.now(timezone.utc):
        raise HTTPException(status_code=429, detail="Too many failed attempts, try again later")

    if not is_valid_uuid4(device_Id):
        raise HTTPException(status_code=401, detail="Invalid device ID")

    user = (
        db.query(User)
        .filter(User.username == payload.username)
        .one_or_none()
    )

    def _record_failure():
        attempts = _login_attempts.setdefault(client_ip, [])
        attempts.append(datetime.now(timezone.utc))
        if len(attempts) >= 3:
            _ip_bans[client_ip] = datetime.now(timezone.utc) + timedelta(hours=2)
            _login_attempts.pop(client_ip, None)

    if not user:
        _record_failure()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    try:
        ph.verify(user.password_hash, payload.password)
    except VerifyMismatchError:
        _record_failure()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Clear any prior failed attempts on success
    _login_attempts.pop(client_ip, None)

    token = secrets.token_urlsafe(32)

    token_hash = hmac.new(
        SERVER_KEY,
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    # LRU session pruning: keep at most 9 existing sessions so the new one makes 10
    existing_sessions = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == user.id)
        .order_by(SessionModel.last_accessed.asc())
        .all()
    )
    if len(existing_sessions) >= 10:
        for old in existing_sessions[: len(existing_sessions) - 9]:
            db.delete(old)

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
    q: str = Query(..., min_length=3),
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
        raise HTTPException(status_code=404, detail="Public key not found")

    user_key = (
        db.query(UserKey)
        .filter(UserKey.user_id == user.id)
        .one_or_none()
    )

    if not user_key:
        raise HTTPException(status_code=404, detail="Public key not found")

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

    # Enforce 25 GiB per-user storage quota
    MAX_USER_STORAGE = 25 * 1024 * 1024 * 1024  # 25 GiB in bytes
    used_bytes = (
        db.query(func.coalesce(func.sum(Media.file_size), 0))
        .filter(Media.uploader_id == user.id)
        .scalar()
    )
    # Read file size before full read for quota check; re-read below
    content = await file.read()
    file_size = len(content)

    if used_bytes + file_size > MAX_USER_STORAGE:
        raise HTTPException(
            status_code=413,
            detail="Storage quota exceeded (25 GiB per user)",
        )

    # validate chunk parameters
    if chunk_index < 0 or chunk_index >= total_chunks:
        raise HTTPException(status_code=400, detail="Invalid chunk_index")

    if total_chunks < 1:
        raise HTTPException(status_code=400, detail="total_chunks must be >= 1")

    if file_size > MAX_CHUNK_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Chunk exceeds maximum size of 256 MiB ({MAX_CHUNK_SIZE} bytes)",
        )

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    if not is_valid_nonce(nonce):
        raise HTTPException(status_code=400, detail="Invalid nonce")

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

    # Enforce total_chunks immutability: the first uploaded chunk locks the value
    prior_chunk = (
        db.query(Media)
        .filter(Media.upload_id == upload_id)
        .first()
    )
    if prior_chunk and prior_chunk.total_chunks != total_chunks:
        raise HTTPException(
            status_code=400,
            detail="total_chunks does not match the value used for previous chunks of this upload",
        )

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


# Per-user WebSocket message timestamps for rate limiting (user_id -> deque of datetimes)
_ws_msg_times: dict[int, deque] = {}

@app.websocket("/chat/ws/{chat_id}")
async def chat_ws(
    websocket: WebSocket,
    chat_id: int,
    token: str = Query(...),
    device_id: str = Query(...),
):
    db: Session = SessionLocal()
    user = None
    try:
        # ── Authenticate BEFORE accepting the connection ───────────────
        if not is_valid_uuid4(device_id):
            await websocket.close(code=4001, reason="Unauthorized")
            return

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

        # Reject duplicate device connection to same chat
        self_conns = manager.active.get(chat_id, {})
        if device_id in self_conns.get(user.id, {}):
            await websocket.close(code=4001, reason="Unauthorized")
            return

        # ── Accept only after auth passes ─────────────────────────────
        await websocket.accept()
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
                "message_type": m.message_type,
                "call_uuid": m.call_uuid,
                "call_status": m.call_status,
                "duration_seconds": m.duration_seconds,
                "epoch_id": m.epoch_id,
                "reply_id": m.reply_id,
                "ciphertext": "" if (m.is_deleted or m.message_type == "call") else m.ciphertext,
                "nonce": "" if (m.is_deleted or m.message_type == "call") else m.nonce,
                "deleted": m.is_deleted,
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

        # ── Main receive loop ──────────────────────────────────────────
        while True:
            try:
                data = await websocket.receive_text()
            except WebSocketDisconnect:
                break
            except Exception:
                break

            # Enforce max message size
            if len(data) > 16384:
                await websocket.close(code=1009, reason="Message too large")
                break

            # Enforce 3 messages/second/user rate limit
            now = datetime.now(timezone.utc)
            times = _ws_msg_times.setdefault(user.id, deque())
            while times and (now - times[0]).total_seconds() > 1.0:
                times.popleft()
            if len(times) >= 3:
                await websocket.close(code=4029, reason="Rate limit exceeded")
                break
            times.append(now)

            try:
                msg = json.loads(data)
            except Exception:
                continue

            if msg.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))

    finally:
        if user is not None:
            manager.disconnect(chat_id, user.id, device_id)
            # Clean up rate-limit state for this user if no more WS connections
            if not any(
                user.id in conns
                for conns in manager.active.values()
            ):
                _ws_msg_times.pop(user.id, None)
        db.close()


# ── Call WebSocket ────────────────────────────────────────────────────

# Per-call rate-limiting: (call_uuid + str(user_id)) -> deque of timestamps
_call_msg_times: dict[str, deque] = {}

@app.websocket("/call/ws/{call_uuid}")
async def call_ws(
    websocket: WebSocket,
    call_uuid: str,
    token: str = Query(...),
    device_id: str = Query(...),
):
    db: Session = SessionLocal()
    user = None
    call = None
    rl_key = ""
    try:
        # 1. Validate device_id format
        if not is_valid_uuid4(device_id):
            await websocket.close(code=4001, reason="Unauthorized")
            return

        # 2. Authenticate (reuses ws_authenticate, same as chat_ws)
        user = ws_authenticate(token, device_id, db)
        token = None  # discard plaintext token
        if not user:
            await websocket.close(code=4001, reason="Unauthorized")
            return

        # 3. Validate call_uuid format
        if not is_valid_uuid4(call_uuid):
            await websocket.close(code=4004, reason="Call not found")
            return

        # 4. Load call record and verify this user is a participant
        call = (
            db.query(CallRecord)
            .filter(CallRecord.call_uuid == call_uuid)
            .one_or_none()
        )
        if not call:
            await websocket.close(code=4004, reason="Call not found")
            return

        if user.id not in (call.initiator_id, call.recipient_id):
            await websocket.close(code=4001, reason="Unauthorized")
            return

        # 5. Reject if call is already in a terminal state
        if call.status in (CallStatus.ended, CallStatus.rejected, CallStatus.missed):
            await websocket.close(code=4010, reason="Call already ended")
            return

        # 6. Reject duplicate connection (one WS per user per call).
        # Exception: allow reconnection if a disconnect grace-period task is pending.
        reconnecting = call_manager.cancel_disconnect_task(call_uuid, user.id)
        if not reconnecting and call_manager.is_participant_connected(call_uuid, user.id):
            await websocket.close(code=4001, reason="Already connected")
            return

        # 7. Accept connection
        await websocket.accept()
        await call_manager.connect(call_uuid, user.id, websocket)

        # 8. Transition: initiated -> ringing when callee connects
        if user.id == call.recipient_id and call.status == CallStatus.initiated:
            call.status = CallStatus.ringing
            db.commit()
            asyncio.ensure_future(call_manager.broadcast(call_uuid, {
                "type": "call_state",
                "status": CallStatus.ringing,
                "call_id": call_uuid,
            }))

        # 9. Main receive loop
        rl_key = call_uuid + str(user.id)  # rate-limit key for this session
        while True:
            try:
                data = await websocket.receive_text()
            except WebSocketDisconnect:
                break
            except Exception:
                break

            # Frame size guard: 4096 bytes covers Opus at 64 kbps with generous headroom
            if len(data) > 4096:
                await websocket.close(code=1009, reason="Message too large")
                break

            # Rate limit: 100 msg/s per user per call (50 pps audio + signaling)
            now_ts = datetime.now(timezone.utc)
            times = _call_msg_times.setdefault(rl_key, deque())
            while times and (now_ts - times[0]).total_seconds() > 1.0:
                times.popleft()
            if len(times) >= 100:
                await websocket.close(code=4029, reason="Rate limit exceeded")
                break
            times.append(now_ts)

            try:
                msg = json.loads(data)
            except Exception:
                continue

            msg_type = msg.get("type")

            # Reload call state from DB before each state-machine check
            db.refresh(call)

            if msg_type == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))

            elif msg_type == "offer":
                # Only the initiator may send an offer
                if user.id != call.initiator_id:
                    await websocket.send_text(json.dumps({
                        "type": "error", "detail": "Only initiator sends offer",
                    }))
                    continue
                if call.status not in (CallStatus.initiated, CallStatus.ringing):
                    continue
                # Relay offer to callee — caller_id sourced from DB to prevent spoofing
                await call_manager.send_to(call_uuid, call.recipient_id, {
                    "type": "offer",
                    "sdp": msg.get("sdp", ""),
                    "wrapped_call_key": msg.get("wrapped_call_key", ""),
                    "caller_id": call.initiator_id,
                })

            elif msg_type == "answer":
                if user.id != call.recipient_id:
                    continue
                if call.status != CallStatus.ringing:
                    continue
                call.status = CallStatus.accepted
                call.answered_at = datetime.now(timezone.utc)
                db.commit()
                call_manager.cancel_timeout(call_uuid)
                await call_manager.send_to(call_uuid, call.initiator_id, {
                    "type": "answer",
                    "sdp": msg.get("sdp", ""),
                })
                asyncio.ensure_future(call_manager.broadcast(call_uuid, {
                    "type": "call_state",
                    "status": CallStatus.accepted,
                    "call_id": call_uuid,
                }))

            elif msg_type == "ice_candidate":
                other_id = (
                    call.recipient_id if user.id == call.initiator_id
                    else call.initiator_id
                )
                await call_manager.send_to(call_uuid, other_id, {
                    "type": "ice_candidate",
                    "candidate": msg.get("candidate", ""),
                    "sdp_mid": msg.get("sdp_mid", ""),
                    "sdp_mline_index": msg.get("sdp_mline_index", 0),
                    "from_user_id": user.id,
                })

            elif msg_type == "audio_frame":
                # Only relay when the call is active; server never inspects `data`
                if call.status != CallStatus.accepted:
                    continue
                other_id = (
                    call.recipient_id if user.id == call.initiator_id
                    else call.initiator_id
                )
                relay: dict = {
                    "type": "audio_frame",
                    "data": msg.get("data", ""),
                    "seq": msg.get("seq", 0),
                    "nonce": msg.get("nonce", ""),
                }
                if msg.get("is_init"):
                    relay["is_init"] = True
                    relay["mime"] = msg.get("mime", "")
                await call_manager.send_to(call_uuid, other_id, relay)

            elif msg_type == "reject":
                if user.id != call.recipient_id:
                    continue
                if call.status not in (CallStatus.initiated, CallStatus.ringing):
                    continue
                call_msg = _finalize_call(db, call, CallStatus.rejected)
                call_manager.cancel_timeout(call_uuid)
                asyncio.ensure_future(call_manager.broadcast(call_uuid, {
                    "type": "rejected",
                    "call_id": call_uuid,
                }))
                asyncio.ensure_future(manager.broadcast(call.chat_id, _call_chat_ws_payload(call_msg)))
                asyncio.ensure_future(notify_call_event(
                    call_uuid=call_uuid,
                    chat_id=call.chat_id,
                    recipient_user_id=call.initiator_id,
                    caller_id=call.recipient_id,
                    event_type="call_ended",
                ))
                break

            elif msg_type == "end":
                if call.status in (CallStatus.ended, CallStatus.rejected, CallStatus.missed):
                    break
                other_id = (
                    call.recipient_id if user.id == call.initiator_id
                    else call.initiator_id
                )
                call_msg = _finalize_call(db, call, CallStatus.ended)
                call_manager.cancel_timeout(call_uuid)
                asyncio.ensure_future(call_manager.broadcast(call_uuid, {
                    "type": "ended",
                    "call_id": call_uuid,
                }))
                asyncio.ensure_future(manager.broadcast(call.chat_id, _call_chat_ws_payload(call_msg)))
                asyncio.ensure_future(notify_call_event(
                    call_uuid=call_uuid,
                    chat_id=call.chat_id,
                    recipient_user_id=other_id,
                    caller_id=user.id,
                    event_type="call_ended",
                ))
                break

    finally:
        if user is not None and call is not None:
            call_manager.disconnect(call_uuid, user.id)
            db.refresh(call)
            if call.status not in (CallStatus.ended, CallStatus.rejected, CallStatus.missed):
                other_id = (
                    call.recipient_id if user.id == call.initiator_id
                    else call.initiator_id
                )
                # 10-second grace period: finalize only if the user doesn't reconnect
                call_manager.schedule_disconnect_finalize(
                    call_uuid, user.id,
                    _disconnect_finalize_after_delay(call_uuid, user.id, other_id, 10.0),
                )
        # Clean up rate-limit state
        _call_msg_times.pop(rl_key, None)
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
            "message_type": m.message_type,
            "call_uuid": m.call_uuid,
            "call_status": m.call_status,
            "duration_seconds": m.duration_seconds,
            "epoch_id": m.epoch_id,
            "reply_id": m.reply_id,
            "ciphertext": "" if (m.is_deleted or m.message_type == "call") else m.ciphertext,
            "nonce": "" if (m.is_deleted or m.message_type == "call") else m.nonce,
            "deleted": m.is_deleted,
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

    if not epoch or not epoch.wrapped_key_a or not epoch.wrapped_key_b:
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

    if not is_valid_nonce(payload.nonce):
        raise HTTPException(status_code=400, detail="Invalid nonce")

    if payload.reply_id is not None:
        replied = (
            db.query(Message)
            .filter(
                Message.id == payload.reply_id,
                Message.chat_id == chat_id,
            )
            .one_or_none()
        )
        if not replied:
            raise HTTPException(
                status_code=404,
                detail="Reply target not found in this chat",
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

            if media.uploader_id != user.id:
                db.rollback()
                raise HTTPException(
                    status_code=403,
                    detail=f"Media {mid} was not uploaded by you",
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
            "message_type": msg.message_type,
            "call_uuid": msg.call_uuid,
            "call_status": msg.call_status,
            "duration_seconds": msg.duration_seconds,
            "epoch_id": msg.epoch_id,
            "reply_id": msg.reply_id,
            "ciphertext": msg.ciphertext,
            "nonce": msg.nonce,
            "deleted": False,
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


@app.delete("/chat/{chat_id}/message/{message_id}", status_code=200)
async def delete_message(
    chat_id: int,
    message_id: int,
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

    msg = (
        db.query(Message)
        .filter(
            Message.id == message_id,
            Message.chat_id == chat_id,
        )
        .one_or_none()
    )

    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")

    if msg.sender_id != user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own messages")

    if msg.is_deleted:
        raise HTTPException(status_code=409, detail="Message already deleted")

    msg.is_deleted = True
    msg.deleted_at = datetime.now(timezone.utc)
    db.commit()

    asyncio.ensure_future(manager.broadcast(chat_id, {
        "type": "message_deleted",
        "message_id": message_id,
    }))

    return {"status": "deleted", "message_id": message_id}


# ── Call REST endpoints ────────────────────────────────────────────────

@app.post("/call/{chat_id}/initiate", status_code=201, response_model=CallInitiateResponse)
async def initiate_call(
    chat_id: int,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    # 1. Verify caller is a member of this chat
    chat = (
        db.query(Chat)
        .filter(
            Chat.id == chat_id,
            or_(Chat.user_a_id == user.id, Chat.user_b_id == user.id),
        )
        .one_or_none()
    )
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    recipient_id = chat.user_b_id if chat.user_a_id == user.id else chat.user_a_id

    # 2. Reject if there is already an active call in this chat
    existing = (
        db.query(CallRecord)
        .filter(
            CallRecord.chat_id == chat_id,
            CallRecord.status.in_([
                CallStatus.initiated,
                CallStatus.ringing,
                CallStatus.accepted,
            ]),
        )
        .one_or_none()
    )
    if existing:
        raise HTTPException(status_code=409, detail="A call is already active in this chat")

    # 3. Create the call record
    call_uuid = str(uuid.uuid4())
    call = CallRecord(
        call_uuid=call_uuid,
        chat_id=chat_id,
        initiator_id=user.id,
        recipient_id=recipient_id,
        status=CallStatus.initiated,
    )
    db.add(call)
    db.commit()
    db.refresh(call)

    # 4. Schedule missed-call timeout (30 seconds)
    call_manager.schedule_missed_timeout(
        call_uuid=call_uuid,
        callback=lambda: asyncio.ensure_future(
            _handle_missed_call(call_uuid, chat_id, user.id, recipient_id)
        ),
        delay=30.0,
    )

    # 5a. Notify callee devices connected to the chat WebSocket right now
    ws_payload = {
        "type": "call_incoming",
        "call_id": call_uuid,
        "chat_id": chat_id,
        "caller_id": user.id,
    }
    asyncio.ensure_future(manager.broadcast(chat_id, ws_payload, exclude_user_id=user.id))

    # 5b. Notify callee devices NOT already reached via WebSocket via FCM
    already_notified = manager.active_device_ids(chat_id, recipient_id)
    asyncio.ensure_future(notify_call_event(
        call_uuid=call_uuid,
        chat_id=chat_id,
        recipient_user_id=recipient_id,
        caller_id=user.id,
        event_type="call_incoming",
        exclude_device_ids=already_notified,
    ))

    return {
        "call_id": call_uuid,
        "chat_id": chat_id,
        "initiator_id": user.id,
        "recipient_id": recipient_id,
        "status": call.status,
        "created_at": call.created_at.isoformat(),
    }


@app.get("/call/{chat_id}/history", response_model=CallHistoryResponse)
async def call_history(
    chat_id: int,
    before: str | None = Query(None),
    limit: int = Query(20, le=50),
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    # Verify chat membership
    chat = (
        db.query(Chat)
        .filter(
            Chat.id == chat_id,
            or_(Chat.user_a_id == user.id, Chat.user_b_id == user.id),
        )
        .one_or_none()
    )
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")

    q = db.query(CallRecord).filter(CallRecord.chat_id == chat_id)
    if before:
        try:
            before_dt = datetime.fromisoformat(before)
            q = q.filter(CallRecord.created_at < before_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid cursor")

    calls = q.order_by(desc(CallRecord.created_at)).limit(limit).all()

    def _duration(c: CallRecord) -> int | None:
        if c.answered_at and c.ended_at:
            return int((_as_utc(c.ended_at) - _as_utc(c.answered_at)).total_seconds())
        return None

    entries = [
        {
            "call_id": c.call_uuid,
            "initiator_id": c.initiator_id,
            "recipient_id": c.recipient_id,
            "status": c.status,
            "created_at": c.created_at.isoformat(),
            "answered_at": c.answered_at.isoformat() if c.answered_at else None,
            "ended_at": c.ended_at.isoformat() if c.ended_at else None,
            "duration_seconds": _duration(c),
        }
        for c in calls
    ]

    next_cursor = calls[-1].created_at.isoformat() if calls else None

    return {"calls": entries, "next_cursor": next_cursor}
