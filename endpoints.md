# Omnis Chat API — REST Specification

## Base URL
```
http://localhost:8000
```

All requests and responses use JSON.  
All timestamps are UTC ISO-8601.

---

## Authentication Model

Authentication is **session-based**, scoped to a `(token, device_id)` pair.

### Headers (required on authenticated endpoints)

```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

- `Authorization` contains the session token returned by `POST /auth/login`.
- `X-Device-ID` is a client-generated UUID v4 that identifies the device / browser instance.

Unless explicitly stated otherwise, all endpoints that depend on authentication
require both headers.

---

## Cryptographic Model (High-Level)

- Each user has a long-term **identity keypair**.
- The **public key** is stored on the server.
- The **private key** is encrypted client-side with a passphrase and stored as an
  opaque blob on the server (the server never sees the passphrase).
- Message bodies are treated as opaque payloads; any end-to-end encryption is
  implemented on the client side.

The API exposes endpoints to upload and retrieve identity key material; it does
not provide server-side encryption or decryption of messages.

---

## Health

### GET /

Simple health check.

**Auth:** none

**Response**
```json
{
  "PING": "PONG"
}
```

---

## Auth Endpoints

### POST /auth/signup

Creates a new user and stores initial identity key material.

**Auth:** none

**Request body**
```json
{
  "username": "string",
  "password": "string",
  "identity_pub": "string",
  "encrypted_identity_priv": "string",
  "kdf_salt": "string",
  "aead_nonce": "string"
}
```

**Response — 201 Created**
```json
{
  "id": 1,
  "username": "alice"
}
```

Errors:
- `400` — username already exists

---

### POST /auth/login

Authenticates a user and creates a new session for the device.

**Headers**
```
X-Device-ID: <uuid-v4>
User-Agent: <string> (optional)
```

**Request body**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response — 200 OK**
```json
{
  "token": "string"
}
```

Errors:
- `401` — invalid username or password

---

### POST /auth/logout

Logs out the **current session only**.

**Headers**
```
Authorization: Bearer <token>
```

**Response — 200 OK**
```json
{
  "status": "logged out"
}
```

Errors:
- `401` — invalid or unknown token

---

### GET /auth/me

Returns the authenticated user.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Response — 200 OK**
```json
{
  "id": 1,
  "username": "string"
}
```

Errors:
- `401` — unauthorized

---

### GET /auth/keyblob

Returns the encrypted identity key material for the authenticated user.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Response — 200 OK**
```json
{
  "identity_pub": "string",
  "encrypted_identity_priv": "string",
  "kdf_salt": "string",
  "aead_nonce": "string"
}
```

Errors:
- `401` — unauthorized
- `404` — identity key material not found

---

## Account & Session Management

### GET /users/sessions

Lists all active sessions for the authenticated user.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Response — 200 OK**
```json
[
  {
    "id": 12,
    "device_id": "uuid-v4",
    "user_agent": "string or null",
    "last_accessed": "ISO-8601",
    "created_at": "ISO-8601",
    "expires_at": "ISO-8601 or null",
    "current": true
  }
]
```

The `current` field is `true` only for the session corresponding to the
combination of the provided `Authorization` token and `X-Device-ID`.

Errors:
- `401` — unauthorized

---

### DELETE /users/sessions/revoke/{session_id}

Revokes a specific session belonging to the authenticated user.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Path parameters**
- `session_id` — integer

**Response — 200 OK**
```json
{
  "status": "revoked"
}
```

Errors:
- `401` — unauthorized
- `404` — session not found or does not belong to user

---

### DELETE /users/sessions/revoke_other

Revokes all sessions for the authenticated user **except** the current one.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Response — 200 OK**
```json
{
  "status": "other sessions revoked"
}
```

Errors:
- `401` — unauthorized

---

## User Public Key Endpoints

### POST /user/pkey/publish

Publishes identity key material for the authenticated user. Fails if a key
already exists.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Request body**
```json
{
  "identity_pub": "string",
  "encrypted_identity_priv": "string",
  "kdf_salt": "string",
  "aead_nonce": "string"
}
```

**Response — 201 Created**
```json
{
  "status": "published"
}
```

Errors:
- `401` — unauthorized
- `409` — public key already published

---

### GET /user/pkey/get

Fetches the public identity key for a given username.

**Auth:** none (public lookup)

**Query parameters**
```
username: string (required)
```

**Response — 200 OK**
```json
{
  "username": "string",
  "identity_pub": "string"
}
```

Errors:
- `404` — user not found
- `404` — user has not published a public key

---

## Chat Endpoints

### GET /chat/list

Lists chats for the authenticated user.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Response — 200 OK**
```json
[
  {
    "chat_id": 42,
    "with_user": "other_username"
  }
]
```

Errors:
- `401` — unauthorized

---

### POST /chat/create

Creates a one-to-one chat with another user, identified by username.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Request body**
```json
{
  "username": "target_username"
}
```

**Response — 200 OK**
```json
{
  "chat_id": 42
}
```

If a chat between the two users already exists, the existing `chat_id` is
returned.

Errors:
- `401` — unauthorized
- `404` — target user not found

---

### GET /chat/fetch/{chat_id}

Fetches messages for a chat, in chronological order (oldest to newest).

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Path parameters**
- `chat_id` — integer

**Query parameters**
```
before_id: integer (optional)  # fetch messages with id < before_id
limit: integer (optional, default 50, max 100)
```

**Response — 200 OK**
```json
{
  "messages": [
    {
      "id": 1001,
      "sender_id": 1,
      "epoch_id": 5,
      "ciphertext": "base64-or-opaque-string",
      "nonce": "string",
      "created_at": "ISO-8601"
    }
  ],
  "next_cursor": 1001
}
```

- `next_cursor` is the id of the oldest message in the returned batch, or
  `null` if there are no messages. To page backwards in time, pass this value
  as `before_id` in the next request.
- Each message contains an `epoch_id` field. Use `GET /chat/{chat_id}/{epoch_id}/fetch`
  to retrieve the wrapped epoch key needed for decryption.

Errors:
- `401` — unauthorized
- `404` — chat not found or user is not a member

---

### GET /chat/{chat_id}/{epoch_id}/fetch

Fetches the wrapped epoch key for a specific epoch in a chat.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Path parameters**
- `chat_id` — integer
- `epoch_id` — integer

**Response — 200 OK**
```json
{
  "epoch_id": 5,
  "epoch_index": 1,
  "wrapped_key": "base64-or-opaque-string"
}
```

- `wrapped_key` is the epoch key wrapped for the authenticated user.

Errors:
- `401` — unauthorized
- `404` — chat not found or user is not a member
- `404` — epoch not found

---

### POST /chat/{chat_id}/epoch

Creates a new key epoch for a chat. Epochs are used by clients to rotate
message encryption keys.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Path parameters**
- `chat_id` — integer

**Request body**
```json
{
  "wrapped_key_a": "base64-or-opaque-string",
  "wrapped_key_b": "base64-or-opaque-string"
}
```

**Response — 201 Created**
```json
{
  "epoch_id": 5,
  "epoch_index": 1
}
```

Errors:
- `401` — unauthorized
- `404` — chat not found or user is not a member
- `400` — epoch rotation not allowed yet (message-count gate not satisfied)
- `429` — epoch creation throttled (too frequent requests)

---

### POST /chat/{chat_id}/message

Sends a message in a chat.

**Headers**
```
Authorization: Bearer <token>
X-Device-ID: <uuid-v4>
```

**Path parameters**
- `chat_id` — integer

**Request body**
```json
{
  "epoch_id": 5,
  "ciphertext": "base64-or-opaque-string",
  "nonce": "string"
}
```

**Response — 201 Created**
```json
{
  "id": 1001,
  "epoch_id": 5,
  "created_at": "ISO-8601"
}
```

Errors:
- `401` — unauthorized
- `404` — chat not found or user is not a member
- `409` — unknown epoch
- `409` — stale epoch; a newer epoch exists and must be used
- `409` — epoch not initialized (wrapped keys missing)

---

## Notes & Non-Goals (Current State)

- The server does not perform any encryption or decryption of messages; it
  stores and returns message bodies as provided by clients.
- Identity private keys are stored only in encrypted form; the server does not
  see user passphrases.
- Key epochs and wrapped epoch keys are managed via the `/chat/{chat_id}/epoch`
  endpoint and retrieved individually via `/chat/{chat_id}/{epoch_id}/fetch`.
- Clients should cache epoch keys locally and only request epoch keys for
  epochs they have not yet decrypted.