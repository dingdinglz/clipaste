# clipaste — hardened fork

Paste local clipboard images and copied Markdown files into Claude Code over SSH. Fork of
[hqhq1025/clipaste](https://github.com/hqhq1025/clipaste), maintained here at
[dingdinglz/clipaste](https://github.com/dingdinglz/clipaste).

**This fork changes the security protocol and defaults. Install both ends using
this fork's setup command. Upstream Homebrew packages and old helpers do not
provide these protections.** No fork binary release or Homebrew tap is currently
advertised; install from source.

## What changed

- Clipboard endpoints require a random 256-bit bearer token. Public `/health`
  reveals only version/authentication/mode metadata.
- Tokens are stored separately from image caches, in private configuration
  directories; secrets travel via stdin, not process command lines.
- The local clipboard is **left untouched by default**. SSH image paste still
  works. Explicitly set `CLIPASTE_SERVER_ONLY=0` to enable upstream-style local
  file-path paste.
- Image and Markdown caches expire after **one hour** by default. Cleanup runs at startup and
  approximately once per minute while the daemon runs. Expired images cannot be
  fetched even before the next cleanup pass.
- SSH configuration gets a private backup and an atomic replacement. Setup adds
  narrowly scoped, managed blocks instead of parsing/rebuilding user Host/Match
  sections. Existing foreign helper files and symlinks are not overwritten.
- Private clipboard markers apply to file-copy and raw-image paths; image-file
  symlinks and invalid/oversized images are rejected.
- HTTP requests have bounded headers, connection concurrency, image size and
  I/O timeouts. Host/Origin checks block browser-based access.

See [SECURITY.md](SECURITY.md) for the threat model, limitations and migration.

## Install from source

Install Rust/Cargo, then inspect or clone this repository:

```bash
git clone https://github.com/dingdinglz/clipaste.git
cd clipaste
cargo test --locked
cargo install --path . --locked
```

For a repeatable installation, check out the particular commit you reviewed
before building. `~/.cargo/bin` must be on your PATH. macOS and Windows builds use
the operating system clipboard API. A Linux clipboard host needs a real desktop
session plus `curl` and `xclip` or `wl-clipboard`.

Start the daemon **on the computer whose clipboard you want to share**:

```bash
clipaste
```

Leave that terminal running. In another local terminal:

```bash
clipaste doctor --json
```

No service or login item is installed by these commands. If an upstream service
is already running, stop it before starting this fork; the port cannot be shared.
For macOS, that may mean `brew services stop clipaste`. Do not restart it using
`brew services start clipaste`, which would start the upstream binary again.

## Supported formats

| Clipboard source | Supported inputs | Remote result |
|---|---|---|
| Mac screenshot / copied image pixels | PNG, TIFF, JPEG | PNG image; Claude Code on Linux uses Control+V |
| One image file copied in Mac Finder | `.png`, `.tif`, `.tiff`, `.bmp`, `.jpg`, `.jpeg` (case-insensitive) | Validated and converted to PNG |
| One file copied in Mac Finder | `.md` (UTF-8, no NUL bytes, including empty files) | Exact Markdown bytes in a private remote `.md` file |

Images are limited to 64 MiB; Markdown files to 4 MiB. Symlinks, multiple-file
copies, private-marked clipboard entries and unsupported formats are rejected.
The new copied-file formats are captured on **macOS**; Windows/Linux clipboard
hosts retain their existing image-only capture behavior. Plain copied text is
not automatically turned into an uploaded Markdown file.

**Markdown does not use Claude Code's image-only Control+V binding.** Copy the
`.md` file in Finder, run `clipaste-paste` on the remote, then paste the printed
remote path into Claude. You can also ask Claude to run `clipaste-paste` and read
that path. The helper only transfers the bytes; it never executes Markdown code.

## SSH setup: Mac → Linux Claude Code

On your local clipboard host, while the daemon is running:

```bash
clipaste ssh-setup user@your-server
# Or an existing literal Host alias from ~/.ssh/config:
clipaste ssh-setup myserver
# Non-default SSH port:
clipaste ssh-setup user@your-server -p 22222
```

Setup uploads private credentials and helper scripts through SSH stdin. The
server must support `bash` and `curl`; no sudo is required. It installs
`clipaste-paste` everywhere, and `xclip`/`wl-paste` wrappers on Linux. Unknown
existing files cause setup to stop, rather than overwrite them.

Open a **new SSH connection using the same destination** after setup:

```bash
ssh user@your-server
claude
```

Copy an image locally, then press **Control+V** in remote Claude Code on Linux.
**Not Command+V**: terminal text paste does not forward an image clipboard.

For a remote Mac, Codex CLI, or tools that read image files rather than invoking
clipboard helpers, run `clipaste-paste` on the remote and give its printed path
to the agent. The same helper supports copied `.md` files. Helper files are
private and expire through cleanup on the
next helper invocation after one hour; they are not removed by a system timer.

Keep your desktop user and server account trusted. A remote administrator, or
another process running as your remote Unix account, can still use its token.
This is not a sandbox against those actors.

## Upgrade after adding file support

```bash
cd ~/Developer/clipaste  # or your clone directory
git pull --ff-only
cargo install --path . --locked
```

Stop your existing foreground daemon with Control+C and restart the new binary.
Then rerun `clipaste ssh-setup your-server` locally to update the remote helpers,
and open a new SSH connection. Updating only the daemon is not enough for
Markdown: old remote helpers deliberately reject unknown payload types.

## WSL2

Run the Windows daemon first. Import its token explicitly into WSL using a
private copy accessible to your WSL user:

```bash
clipaste wsl-setup --host 127.0.0.1 --token-file /path/to/private-token-copy
```

On Windows the source token is normally
`%LOCALAPPDATA%\clipaste\token`; on Unix it is
`${XDG_CONFIG_HOME:-$HOME/.config}/clipaste/token`. Unix token imports must be
regular non-symlink files owned by you with permissions `0600`. A mounted Windows
file may need to be copied into your WSL home and `chmod 600` applied first.
Do not put the token itself in shell arguments or chat messages.

An already configured WSL installation can reuse its private token. Host
addresses must be literal IP addresses. Mirrored networking usually uses
`127.0.0.1`; NAT networking may need the Windows host address. Do not expose the
clipboard service publicly to work around networking limitations.

## Privacy settings

| Variable | Default | Meaning |
|---|---|---|
| `CLIPASTE_SERVER_ONLY` | `1` | Leave the local clipboard unchanged; `0` opts into local path normalization |
| `CLIPASTE_CACHE_TTL_SECONDS` | `3600` | Local image/Markdown retention; `0` explicitly opts into indefinite retention |
| `CLIPASTE_BACKEND` | `auto` | Linux only: `auto`, `wayland`, or `x11` |

Environment settings belong to the **daemon**, not the SSH client. Clearing the
clipboard clears the currently served image/file; cached copies remain until expiry.
Closing the daemon stops cleanup; expired files are removed on its next start.
Clipboard history managers may retain independent copies. Expiring a PNG also
invalidates clipboard-history entries that reference its path.

## Development and verification

```bash
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Tests use temporary homes/directories and uniquely named macOS pasteboards,
not the user's general clipboard. Generated shell scripts are syntax-checked.
Linux integration tests require an isolated Xvfb/headless Sway desktop:

```bash
bash tests/linux/run.sh
```

Do not run desktop integration tests against your real desktop sockets or home.
The CI matrix covers macOS, Windows and Linux; local test success on one platform
is not evidence that all others passed. For Linux backend requirements and
compositor caveats, see [the original project](https://github.com/hqhq1025/clipaste).

## License

MIT. Original copyright and license retained in [LICENSE](LICENSE).
