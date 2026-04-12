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
- Messages are append-only; deletion is **soft** (`is_deleted` flag) to preserve reply-thread integrity
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

Chat messages. Stores both regular text messages (`message_type = 'text'`) and
call system messages (`message_type = 'call'`). Call messages are inserted
automatically by the server when a call reaches a terminal state; clients must
render them as call-event cards rather than chat bubbles.

```sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    reply_id INTEGER,
    message_type TEXT NOT NULL DEFAULT 'text', -- 'text' | 'call'

    -- Call system message fields (NULL for message_type = 'text')
    call_uuid        TEXT,    -- UUID v4 matching call_records.call_uuid
    call_status      TEXT,    -- terminal status: 'ended' | 'missed' | 'rejected'
    duration_seconds INTEGER, -- whole seconds from answered_at to ended_at; NULL if never answered

    epoch_id INTEGER,
    ciphertext TEXT NOT NULL DEFAULT '',
    nonce TEXT NOT NULL DEFAULT '',
    is_deleted INTEGER NOT NULL DEFAULT 0,  -- soft delete flag (0 = false, 1 = true)
    deleted_at INTEGER,                      -- UTC timestamp set on soft deletion, NULL otherwise
    created_at INTEGER NOT NULL,

    FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (reply_id) REFERENCES messages(id) ON DELETE SET NULL,
    FOREIGN KEY (epoch_id) REFERENCES chat_epochs(id)
);
```

> **Soft delete behaviour**: When a message is deleted via `DELETE /chat/{chat_id}/message/{message_id}`,
> `is_deleted` is set to `1` and `deleted_at` is set to the current UTC time. The row is retained so
> reply threads remain coherent. Any fetch endpoint that returns this message will return an empty
> string for `ciphertext` and `nonce`, and include `"deleted": true` in the response object.

> **Call message behaviour**: When a call terminates the server inserts a message with
> `message_type = 'call'`. The `call_uuid`, `call_status`, and `duration_seconds` fields
> are populated; `epoch_id`, `ciphertext`, and `nonce` are empty/null. Clients must check
> `message_type` before attempting decryption.

---

## media

Encrypted media chunks stored on disk. Files are sharded into chunks of at most
256 MiB each. All chunks of one logical file share the same `upload_id`.

```sql
CREATE TABLE media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uploader_id INTEGER NOT NULL,
    chat_id INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER NOT NULL,         -- size in bytes
    nonce TEXT NOT NULL,                 -- client-side encryption nonce
    chunk_index INTEGER NOT NULL DEFAULT 0,
    total_chunks INTEGER NOT NULL DEFAULT 1,
    upload_id TEXT NOT NULL,             -- groups chunks of same file
    created_at INTEGER NOT NULL,

    FOREIGN KEY (uploader_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE
);
```

---

## message_media

Join table linking messages to their media attachments.

```sql
CREATE TABLE message_media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    media_id INTEGER NOT NULL,

    UNIQUE(message_id, media_id),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY (media_id) REFERENCES media(id) ON DELETE CASCADE
);
```

---

## call_records

One row per call attempt. The `call_uuid` is used as the path key for the call
WebSocket (`/call/ws/{call_uuid}`) and is referenced by call system messages in
the `messages` table.

```sql
CREATE TABLE call_records (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    call_uuid    TEXT    NOT NULL UNIQUE,              -- UUID v4, used as WS path key
    chat_id      INTEGER NOT NULL,
    initiator_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'initiated', -- see state machine below
    created_at   INTEGER NOT NULL,
    answered_at  INTEGER,                              -- set when callee sends 'answer'; NULL otherwise
    ended_at     INTEGER,                              -- set on any terminal transition; NULL otherwise

    FOREIGN KEY (chat_id)      REFERENCES chats(id) ON DELETE CASCADE,
    FOREIGN KEY (initiator_id) REFERENCES users(id)  ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES users(id)  ON DELETE CASCADE
);
```

**Status values and transitions**

| Status | Meaning |
|--------|---------|
| `initiated` | Call created; callee not yet ringing |
| `ringing` | Callee's call WebSocket has connected |
| `accepted` | Callee sent `answer`; audio exchange active |
| `ended` | Either participant sent `end`, or disconnect grace period expired |
| `rejected` | Callee sent `reject` |
| `missed` | 30-second server timeout elapsed with no answer |

Only `ended`, `rejected`, and `missed` are terminal. The server rejects calls to
`/call/{chat_id}/initiate` while any non-terminal record exists for that chat.

---

## Indexes (Required)

```sql
CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_messages_chat_time ON messages(chat_id, created_at);
CREATE INDEX idx_messages_reply_id ON messages(reply_id);
CREATE INDEX idx_chats_user_a ON chats(user_a_id);
CREATE INDEX idx_chats_user_b ON chats(user_b_id);
CREATE INDEX idx_media_upload_id ON media(upload_id);
CREATE INDEX idx_media_uploader ON media(uploader_id);
CREATE INDEX idx_message_media_message ON message_media(message_id);
-- call records
CREATE INDEX idx_call_records_chat      ON call_records(chat_id);
CREATE INDEX idx_call_records_initiator ON call_records(initiator_id);
CREATE INDEX idx_call_records_recipient ON call_records(recipient_id);
CREATE UNIQUE INDEX idx_call_records_uuid ON call_records(call_uuid);
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
- `/media/upload` → insert into `media` (write chunk to disk)
- `/media/{media_id}/meta` → query `media` (chunk metadata)
- `/media/download/{media_id}` → query `media`, serve file from disk
- `/chat/{chat_id}/message` (with `media_ids`) → insert into `messages` + `message_media`
- `POST /call/{chat_id}/initiate` → insert into `call_records`
- `WS /call/ws/{call_uuid}` → read/update `call_records`; on terminal transition, insert into `messages` (`message_type = 'call'`)
- `GET /call/{chat_id}/history` → query `call_records`

---

## Notes for Production

- Validate UUID v4 format at the API layer
- Consider rotating session tokens
- Add rate limiting if exposed publicly
- Migrate to WAL mode for concurrency

This schema is intentionally boring. That is a feature.
