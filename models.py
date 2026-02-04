from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
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

    epoch_id = Column(Integer, ForeignKey("chat_epochs.id"))
    ciphertext = Column(Text, nullable=False)
    nonce = Column(String(48), nullable=False)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

def init_db():
    Base.metadata.create_all(bind=engine)
