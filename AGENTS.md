# Working on dingdinglz/clipaste

This is a hardened fork of hqhq1025/clipaste. Read README.md and SECURITY.md.
Never install an upstream package and describe it as this fork's hardened build.
No fork Homebrew tap or binary release is currently advertised. Build the reviewed
source with `cargo install --path . --locked`.

## Contribution rules

- Keep fixes testable through pure functions and temporary filesystem fixtures.
- Do not start the daemon, read the user's clipboard, connect their SSH servers,
  or edit their actual SSH/shell configuration while developing or testing.
- Default tests must not access the real HOME. macOS tests use uniquely named
  pasteboards, never the general clipboard. Linux desktop smoke tests use isolated
  Xvfb/headless Sway, temporary HOME/config/cache directories and no desktop sockets.
- Generated shell must be checked with `bash -n` and exercised using temp homes.
- Never put credentials in argv, URLs, logs, errors, clipboard, documentation or
  committed fixtures other than clearly synthetic test tokens.
- Use edit for targeted changes; avoid unrelated rewrites or formatting churn.
- No new dependencies without a strong reason. `getrandom` supplies OS CSPRNG
  tokens; do not replace it with timestamps or noncryptographic hashes.
- Do not disable host-key checks, expose the listener publicly, or silently
  fall back to unauthenticated clipboard transport.

## Changed defaults and protocol

- Local clipboard is untouched by default (`CLIPASTE_SERVER_ONLY=1`). Explicit
  `0` opts into path normalization. This does not affect remote native paste.
- Image cache TTL defaults to 3600 seconds. `CLIPASTE_CACHE_TTL_SECONDS=0`
  explicitly opts into indefinite retention. Cleanup runs at startup and every
  approximately 60 seconds while running; HTTP must reject expired images even
  before cleanup. Do not promise secure erasure or cleanup while stopped.
- Only `/health` is unauthenticated. Clipboard type, image bytes and Markdown
  file bytes require the private bearer token. A healthy bridge diagnosis
  includes an authenticated probe. Image/file endpoints must never mix types.
- Mac file-copy capture supports PNG/TIFF/BMP/JPG/JPEG and UTF-8 `.md` files;
  Markdown stays a file (4 MiB maximum, no NUL). Never execute or render it.
  Native Control+V is image-only; Markdown uses the `clipaste-paste` remote path.
  Do not auto-capture ordinary copied text or claim Windows/Linux file capture.
- SSH setup transfers the token via stdin and installs helpers which read their
  private token file. WSL first-time setup needs `--token-file PATH` importing a
  private token copy; there is no public token-discovery endpoint.
- SSH configuration must preserve unrelated Host/Match/Include sections, use
  private backup/atomic replacement and refuse foreign helper/symlink overwrite.

## Layout

- `src/main.rs`: command-line dispatch and safe defaults.
- `src/security.rs`: private credential lifecycle and authenticated curl.
- `src/server.rs`: bounded loopback HTTP, metadata and authenticated images/files.
- `src/common.rs`: image validation, private cache, TTL and shared utilities.
- `src/ssh_setup.rs`: safe SSH config, generated shell, WSL setup.
- `src/doctor.rs`: role classification and diagnostics.
- `src/macos.rs`, `windows.rs`, `linux.rs`: clipboard backends.

## Build and tests

```bash
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Report the actual platform tested. Linux-only code requires Linux CI or a Linux
container; macOS success is not proof of Windows/Linux runtime correctness.
Opt-in Linux integration: `bash tests/linux/run.sh` (see README prerequisites).

A fresh upstream service may already own port 18340. Do not kill it or alter login
items automatically. Inform the user before any installation/service migration.
`doctor` reports no-image as a warning, but missing credentials, broken helper
PATH precedence and authentication failures must not be reported as success.

## Releasing

Version in Cargo.toml and common::VERSION must match. Fork versions use a
`-dingdinglz.N` prerelease suffix. Run the CI matrix and package preflight before
creating an explicitly requested release/tag. Do not rewrite upstream tags, push
to upstream, or create a release merely because source fixes were requested.
