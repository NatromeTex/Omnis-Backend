# SQLite Database Schema — Private Chat API

This schema is derived directly from the REST API specification.
All timestamps are stored as UNIX epoch seconds.
Foreign keys must be enabled.

```sql
PRAGMA foreign_keys = ON;
```

---

## Design Decisions

- `device_id` uses **UUID v4** (TEXT, canonical string form)
- Users are global
- Devices are per-user
- Sessions are per-user per-device
- Chats are **1-to-1 only**
- Messages are append-only
- Strong foreign-key integrity
- No premature abstractions

---

## users

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
```
---

## sessions

Active login sessions bound to a device.

```sql
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id TEXT NOT NULL, -- UUID v4
    session_token TEXT NOT NULL UNIQUE,
    user_agent TEXT,
    created_at INTEGER NOT NULL,
    last_accessed INTEGER,
    expires_at INTEGER,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

---

## chats

Private chat between exactly two users.

Invariant:
Always store the smaller user id as `user_a_id`.

```sql
CREATE TABLE chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_a_id INTEGER NOT NULL,
    user_b_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,

    UNIQUE(user_a_id, user_b_id),
    FOREIGN KEY (user_a_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (user_b_id) REFERENCES users(id) ON DELETE CASCADE
);
```

---

## messages

Chat messages.

```sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL,

    FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
);
```

---

## Indexes (Required)

```sql
CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_messages_chat_time ON messages(chat_id, created_at);
CREATE INDEX idx_chats_user_a ON chats(user_a_id);
CREATE INDEX idx_chats_user_b ON chats(user_b_id);
```

---

## API Mapping Summary

- `/auth/register` → `devices`
- `/auth/signup` → `users`
- `/auth/login` → `sessions`
- `/auth/logout` → delete from `sessions`
- `/users/search` → query `users` (partial username match)
- `/chats` → query `chats`
- `/chats/{chat_id}` → query `messages`
- `/chats/{chat_id}/messages` → insert into `messages`

---

## Notes for Production

- Validate UUID v4 format at the API layer
- Consider rotating session tokens
- Add rate limiting if exposed publicly
- Migrate to WAL mode for concurrency

This schema is intentionally boring. That is a feature.
