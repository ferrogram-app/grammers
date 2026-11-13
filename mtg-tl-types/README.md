# mtg-tl-types

Rust `struct` and `enum` types for the [Type Language] definitions, generated at build time
from `tl/api.tl` and `tl/mtproto.tl` (the current API layer is in `LAYER`). Each type implements
`Serializable` and `Deserializable` as described in [Binary Data Serialization].

Telegram documentation this crate implements:

- [Type Language]
- [Binary Data Serialization]
- [API layers](https://core.telegram.org/api/layers)

[Type Language]: https://core.telegram.org/mtproto/TL
[Binary Data Serialization]: https://core.telegram.org/mtproto/serialize
