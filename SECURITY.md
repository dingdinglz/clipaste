# Security model of this fork

This is a security-hardening fork, not a claim of complete security or an
independent certification. Its protocol is intentionally incompatible with
unauthenticated upstream clipboard helpers.

## Intended boundary

- A trusted desktop user runs the clipboard daemon without administrator rights.
- Only explicitly configured, trusted SSH/WSL accounts receive its credential.
- The daemon binds `127.0.0.1:18340`. Do not expose it on a public address.
- `/clipboard/type` and `/clipboard/image` require a 256-bit OS-random bearer
  token. `/health` is public metadata and exposes neither the image nor its
  presence. Diagnostic success requires an authenticated clipboard-state probe.
- Normal SSH transport remains encrypted and uses normal host-key checking.
  No SSH verification bypass is installed.

Other accounts that merely reach the remote loopback port no longer get
unauthenticated clipboard access. However, an administrator/root, an attacker
running as your desktop/remote account, or a process that can read its credential
is **inside the trust boundary**. A configured server may read each staged image
while connected; access is not restricted to a user pressing paste.

All configured remotes share the desktop daemon's credential. Compromising one
trusted account compromises that credential. Per-host revocation is not
implemented. For separate trust domains, use separate desktop accounts/daemons,
or do not bridge the clipboard.

## Credentials

Unix: `${XDG_CONFIG_HOME:-$HOME/.config}/clipaste/token`.
Windows: `%LOCALAPPDATA%\clipaste\token`.

Tokens are not image cache files. On Unix, directories are `0700`, tokens `0600`,
and foreign owners/symlinks are rejected. On Windows, protection relies on the
user profile's inherited ACLs; do not use a shared or permissive LOCALAPPDATA.
The filesystem must support atomic renames and hard-link publication for initial
token creation (normal Unix filesystems and NTFS do). Failure is explicit.

Secrets are passed through SSH/curl stdin, not arguments, URLs or logs. Curl
ignores user curlrc files and proxy settings for clipboard requests. Credential
files and setup stdin are still accessible to the same account and administrators.
Protect diagnostic logs, backups and shell tracing; do not run helpers under
`bash -x` or an untrusted SSH wrapper.

To revoke a credential, stop the daemon, remove its token file, restart it, and
rerun setup for every trusted remote. Remove obsolete remote token copies and
managed SSH blocks. Do not post a token in an issue or paste it into Claude.

## Image handling and retention

The fork leaves the local clipboard unchanged by default. It still automatically
observes qualifying images and stores them in its private cache. This is not an
explicit-send-only tool. Image-file copies and raw image bytes respect the
recognized privacy markers; arbitrary applications need not supply those markers.

Images expire after 3600 seconds by default. They become unavailable over HTTP
when expired, and regular managed cache files are deleted at startup and at
approximately 60-second intervals while the daemon runs. This is deletion, **not
secure erasure**; disk snapshots, backups and clipboard history may retain copies.
If the daemon is stopped, deletion waits until the next run. A new copy of the
same image can refresh retention. `CLIPASTE_CACHE_TTL_SECONDS=0` is an explicit
opt-in to indefinite retention.

Remote `clipaste-paste` files live in a private directory. Its old images are
cleaned on subsequent helper invocations, not by a scheduler. The native clipboard
wrappers use private temporary files and cleanup traps. Killing processes
abnormally can leave files behind; no secure-erasure guarantee is made.

Images are bounded to 64 MiB; image decoding has allocation/dimension limits.
HTTP workers, header sizes and I/O waits are bounded. These are defenses in depth,
not protection against a hostile process already executing as your user.

## Setup safety and migration

SSH config updates use an exact-destination managed block, private original-file
backup and atomic replacement. Existing unrelated Host/Match/Include sections
are retained, not reinterpreted. Foreign helper files and symlinks are rejected.
Do not automatically delete a conflicting file: inspect it and move it yourself
if appropriate. Remote and local setup are not a distributed transaction: an
SSH disconnect or local failure can still leave a partial remote installation;
read the error and rerun after resolving it.

Do not start the upstream Homebrew service alongside this fork. Source-install
this fork and rerun setup so both ends have the authenticated protocol. The
repository does not advertise an upstream tag or asset as a hardened release.

Public health metadata is discovery, not a cryptographic proof of server
identity. A local service impersonating a daemon, compromised SSH client, modified
helper, or hostile curl executable is outside the trusted-endpoint assumptions.
Authentication does not replace trusting the machine and tools holding the token.

## Reporting

Avoid publishing screenshots, tokens, private SSH configurations or customer
data. Report a minimal reproducer and affected commit at
https://github.com/dingdinglz/clipaste/issues. Do not treat passing tests or a
clean dependency-advisory scan as proof that no vulnerabilities remain.
