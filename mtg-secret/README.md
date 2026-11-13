# mtg-secret

Planned, not started. Secret chats (end-to-end encrypted, MTProto 2.0 layer): key exchange with
Diffie-Hellman (`messages.requestEncryption`, `acceptEncryption`), message encryption and decryption,
key fingerprint (visualization), `messages.sendEncrypted*`, state per chat (`in_seq_no`, `out_seq_no`, layer
negotiation, TTL, resend). Uses `mtg-crypto`; chat storage stays in the application.

Telegram documentation this crate will implement:

- [End-to-End Encryption, Secret Chats](https://core.telegram.org/api/end-to-end)
- [Perfect Forward Secrecy in Secret Chats](https://core.telegram.org/api/end-to-end/pfs)
- [Security guidelines](https://core.telegram.org/mtproto/security_guidelines)
