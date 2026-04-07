from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Boolean,
    Index,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    create_engine,
    event,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.engine import Engine
import sqlite3

@event.listens_for(Engine, "connect")
def enable_sqlite_foreign_keys(dbapi_connection, _):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

DATABASE_URL = "sqlite:///chat.db"

engine = create_engine(
    DATABASE_URL,
    future=True,
    echo=False,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(128), nullable=False, unique=True)
    password_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

class UserKey(Base):
    __tablename__ = "user_keys"

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)

    identity_pub = Column(String(128), nullable=False)

    encrypted_identity_priv = Column(Text, nullable=False)
    kdf_salt = Column(String(64), nullable=False)
    aead_nonce = Column(String(48), nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id = Column(String(36), nullable=False)  # UUID v4
    session_token_hash = Column(String(128), nullable=False, unique=True)
    user_agent = Column(String(64), nullable=True)
    last_accessed = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime, nullable=True)

    user = relationship("User")


class DevicePushToken(Base):
    __tablename__ = "device_push_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id = Column(String(36), nullable=False)
    platform = Column(String(16), nullable=False, default="android")
    fcm_token = Column(Text, nullable=False, unique=True)

    enabled = Column(Boolean, nullable=False, default=True)
    failure_count = Column(Integer, nullable=False, default=0)
    last_error = Column(String(128), nullable=True)
    invalid_since = Column(DateTime, nullable=True)
    last_success_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    user = relationship("User")

    __table_args__ = (
        UniqueConstraint("user_id", "device_id", "platform"),
        Index("ix_device_push_tokens_user", "user_id"),
    )

class ChatEpoch(Base):
    __tablename__ = "chat_epochs"

    id = Column(Integer, primary_key=True)
    chat_id = Column(Integer, ForeignKey("chats.id", ondelete="CASCADE"))
    epoch_index = Column(Integer, nullable=False)

    wrapped_key_a = Column(Text, nullable=False)
    wrapped_key_b = Column(Text, nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("chat_id", "epoch_index"),)

class Chat(Base):
    __tablename__ = "chats"

    id = Column(Integer, primary_key=True)
    user_a_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_b_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        UniqueConstraint("user_a_id", "user_b_id"),
    )


class Media(Base):
    __tablename__ = "media"

    id = Column(Integer, primary_key=True)
    uploader_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    chat_id = Column(
        Integer,
        ForeignKey("chats.id", ondelete="CASCADE"),
        nullable=False,
    )
    mime_type = Column(String(128), nullable=False)
    file_path = Column(Text, nullable=False)
    file_size = Column(Integer, nullable=False)  # size in bytes
    nonce = Column(String(48), nullable=False)  # client-side encryption nonce
    chunk_index = Column(Integer, nullable=False, default=0)
    total_chunks = Column(Integer, nullable=False, default=1)
    upload_id = Column(String(64), nullable=False)  # groups chunks together

    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        Index("ix_media_upload_id", "upload_id"),
        Index("ix_media_uploader", "uploader_id"),
    )


class MessageMedia(Base):
    """Join table linking messages to media attachments."""
    __tablename__ = "message_media"

    id = Column(Integer, primary_key=True)
    message_id = Column(
        Integer,
        ForeignKey("messages.id", ondelete="CASCADE"),
        nullable=False,
    )
    media_id = Column(
        Integer,
        ForeignKey("media.id", ondelete="CASCADE"),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_message_media_message", "message_id"),
        UniqueConstraint("message_id", "media_id"),
    )


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True)
    chat_id = Column(
        Integer,
        ForeignKey("chats.id", ondelete="CASCADE"),
        nullable=False,
    )
    sender_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    reply_id = Column(
        Integer, 
        ForeignKey("messages.id", ondelete="SET NULL"), 
        nullable=True,
    )

    epoch_id = Column(Integer, ForeignKey("chat_epochs.id"))
    ciphertext = Column(Text, nullable=False)
    nonce = Column(String(48), nullable=False)

    is_deleted = Column(Boolean, nullable=False, default=False)
    deleted_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("ix_messages_chat_created", "chat_id", "created_at"),
        Index("ix_messages_reply_id", "reply_id"),
    )


UPLOAD_DIR = "uploads"


def init_db():
    import os
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    Base.metadata.create_all(bind=engine)
