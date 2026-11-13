# Ferrogram fork

This is the Ferrogram project's own copy of grammers (MIT OR Apache-2.0, original authors keep their
copyright notices). It is developed independently: `master` here is the line the Ferrogram core builds on.

- `origin` = `ferrogram-app/grammers` (we push here). `upstream` = https://codeberg.org/Lonami/grammers,
  read-only (push disabled); look at it with `git fetch upstream && git log master..upstream/master`,
  take what we need with `git cherry-pick`, never an automatic merge.
- Ferrogram pins this repo by commit (`rev = "..."` in `[patch.crates-io]` of the core and the apps):
  after pushing a change here, bump that rev.
- Changes so far (see ferrogram core `doc/security.md`): constant-time msg_key compare, no panics on hostile
  server input, odd server msg_id, padding 12..=1024, duplicate drop, msg_id time window.
- Not done: PFS (temporary keys), MTProxy transport, `dc_options` enumeration.
