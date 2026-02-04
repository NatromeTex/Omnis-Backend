from pydantic import BaseModel

class SignupRequest(BaseModel):
    username: str
    password: str

    identity_pub: str
    encrypted_identity_priv: str
    kdf_salt: str
    aead_nonce: str

class AuthRequest(BaseModel):
    username: str
    password: str

class ChatRequest(BaseModel):
    username: str

class EpochRequest(BaseModel):
    wrapped_key_a: str
    wrapped_key_b: str

class MessageRequest(BaseModel):
    epoch_id: int
    ciphertext: str
    nonce: str

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