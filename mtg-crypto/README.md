# mtg-crypto

Cryptography for Telegram: AES-IGE, MTProto 2.0 message encryption (`msg_key`, padding),
authorization keys, RSA for the key exchange, `pq` factorization, transport obfuscation and
the two-factor (SRP) password check.

Telegram documentation this crate implements:

- [MTProto description](https://core.telegram.org/mtproto/description): AES-IGE, `msg_key`, encrypted messages
- [Creating an authorization key](https://core.telegram.org/mtproto/auth_key): RSA, `pq`, safe-prime checks
- [Security guidelines](https://core.telegram.org/mtproto/security_guidelines)
- [Transport obfuscation](https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation)
- [Two-factor authentication (SRP)](https://core.telegram.org/api/srp)
