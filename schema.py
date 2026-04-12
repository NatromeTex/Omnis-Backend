from pydantic import BaseModel, Field
from typing import Optional

class SignupRequest(BaseModel):
    username: str = Field(..., min_length=5, max_length=32)
    password: str = Field(..., min_length=6)

    identity_pub: str
    encrypted_identity_priv: str
    kdf_salt: str
    aead_nonce: str

class AuthRequest(BaseModel):
    username: str = Field(..., min_length=5, max_length=32)
    password: str = Field(..., min_length=6)

class ChatRequest(BaseModel):
    username: str

class EpochRequest(BaseModel):
    wrapped_key_a: str
    wrapped_key_b: str

class MessageRequest(BaseModel):
    epoch_id: int
    ciphertext: str
    nonce: str
    reply_id: Optional[int] = None
    media_ids: Optional[list[int]] = None

class LogoutRequest(BaseModel):
    session_id: int
    all: bool

class PublishRequest(BaseModel):
    identity_pub: str
    encrypted_identity_priv: str
    kdf_salt: str
    aead_nonce: str

class PKeyResponse(BaseModel):
    username: str
    identity_pub: str


class RegisterFcmTokenRequest(BaseModel):
    fcm_token: str
    platform: str = "android"


class DeviceFcmTokenResponse(BaseModel):
    id: int
    device_id: str
    platform: str
    enabled: bool
    failure_count: int
    invalid_since: Optional[str] = None


class CallInitiateResponse(BaseModel):
    call_id: str
    chat_id: int
    initiator_id: int
    recipient_id: int
    status: str
    created_at: str


class CallHistoryEntry(BaseModel):
    call_id: str
    initiator_id: int
    recipient_id: int
    status: str
    created_at: str
    answered_at: Optional[str] = None
    ended_at: Optional[str] = None
    duration_seconds: Optional[int] = None


class CallHistoryResponse(BaseModel):
    calls: list[CallHistoryEntry]
    next_cursor: Optional[str] = None