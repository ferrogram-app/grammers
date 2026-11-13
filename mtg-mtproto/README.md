# mtg-mtproto

The [Mobile Transport Protocol] without any I/O: transports, plain and encrypted message
state, the authorization key exchange, and parsing of service messages.

Telegram documentation this crate implements:

- [MTProto description](https://core.telegram.org/mtproto/description)
- [Transports](https://core.telegram.org/mtproto/mtproto-transports): abridged, intermediate, full, obfuscated
- [Creating an authorization key](https://core.telegram.org/mtproto/auth_key)
- [Service messages](https://core.telegram.org/mtproto/service_messages) and
  [messages about messages](https://core.telegram.org/mtproto/service_messages_about_messages):
  containers, acks, `bad_msg_notification`, salts, gzip
- [Security guidelines](https://core.telegram.org/mtproto/security_guidelines)

[Mobile Transport Protocol]: https://core.telegram.org/mtproto
