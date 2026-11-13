# mtg-calls

Planned, not started. Call signalling and key exchange: `phone.requestCall`, `acceptCall`, `confirmCall`,
`discardCall`, the `UpdatePhoneCall*` updates, Diffie-Hellman key and the emoji fingerprint, relay (reflector)
connection data, group calls (`phone.joinGroupCall`). The media stack (audio, video, WebRTC) is a separate decision.

Telegram documentation this crate will implement:

- [Voice calls](https://core.telegram.org/api/end-to-end/voice-calls)
- [Video calls](https://core.telegram.org/api/end-to-end/video-calls)
- [Group calls](https://core.telegram.org/api/calls)
