# Omnis Backend

## Overview
Omnis Backend is a FastAPI-based server for a secure, end-to-end encrypted chat application. It handles authentication, session management, user public key distribution, chat creation, epoch management, and message storage while treating message bodies and private keys as opaque encrypted blobs.

For the complete REST API contract, see [endpoints.md](endpoints.md). For client behavior and cryptography requirements that pair with these endpoints, see [frontend.md](frontend.md).

## What it does
- Session-based authentication with per-device sessions.
- Stores encrypted identity key material and exposes public identity keys.
- Manages one-to-one chats, epochs, and message metadata.
- End-to-end encrypted voice calls relayed over WebSocket with a custom audio frame protocol.
- Persists data via SQLAlchemy models.

## Tech stack
- FastAPI
- SQLAlchemy
- Argon2 password hashing

## Configuration
- `SERVER_KEY` environment variable is required for HMAC hashing of session tokens.
- `FIREBASE_CREDENTIALS_PATH` (optional) points to a Firebase service-account JSON file.
	If not set, push notifications are disabled but the rest of the API works.

## Real-time Delivery and Push Model
- Real-time chat delivery is WebSocket-first via `/chat/ws/{chat_id}`.
- REST fetch (`/chat/fetch/{chat_id}`) is used for scrollback/pagination and reconnect fallback.
- Android FCM push is used only as a wake signal when recipient devices are not actively connected to that chat WebSocket.
- Push payloads include wake metadata and generic text only; clients fetch encrypted message data after wake.
- The backend never includes ciphertext, epoch keys, or private key material in FCM payloads.

## Voice Call Model
- Calls are initiated via `POST /call/{chat_id}/initiate` and signaled over a dedicated call WebSocket (`/call/ws/{call_uuid}`).
- Audio is encrypted end-to-end on the client (AES-256-GCM with a per-call session key) and relayed opaquely by the server — the server never sees plaintext audio.
- The call session key is derived using the same ECDH + HKDF + AES-GCM wrapping mechanism as epoch keys.
- Each call transitions through a server-tracked state machine (`initiated → ringing → accepted → ended/rejected/missed`).
- A 30-second server-side timeout marks unanswered calls as `missed`.
- A 10-second client-disconnect grace period is applied before a call is finalized, allowing brief network interruptions to recover without ending the call.

## Files of interest
- Application entrypoint: [main.py](main.py)
- Data models: [models.py](models.py)
- API schemas: [schema.py](schema.py)
- API spec: [endpoints.md](endpoints.md)
- Frontend/crypto spec: [frontend.md](frontend.md)

## Notes
This server never decrypts user messages or identity private keys. All encryption and key derivation happen on the client, and the backend stores only encrypted blobs and metadata. Refer to [frontend.md](frontend.md) for the cryptographic contract that clients must follow.

## License
This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for the full license text.

All previous versions and all future versions of this software are covered by this same license unless explicitly stated otherwise in writing by the copyright holder.