# mtg-client

A high-level Telegram client: connect, sign in, make RPC calls, receive updates, send and
download messages and files. Built on the other `mtg-*` crates.

Telegram documentation this crate implements:

- [Telegram API](https://core.telegram.org/api): methods and objects
- [Authorization](https://core.telegram.org/api/auth) and [two-factor (SRP) passwords](https://core.telegram.org/api/srp)
- [Working with updates](https://core.telegram.org/api/updates)
- [Files](https://core.telegram.org/api/files)
- [Message entities](https://core.telegram.org/api/entities)
- [Error handling](https://core.telegram.org/api/errors)
- [Obtaining `api_id`](https://core.telegram.org/api/obtaining_api_id)

Depend on it from git and keep every `mtg-*` crate on the same revision:

```toml
mtg-client = { git = "https://github.com/ferrogram-app/mtg.git", rev = "<commit>" }
```

`mtg-tl-types` (needed for raw `client.invoke` calls) is re-exported:

```rust
use mtg_client::mtg_tl_types as tl;
```
