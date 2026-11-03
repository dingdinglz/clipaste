# This fork has no advertised prebuilt Windows release yet.
# Fail closed instead of downloading an unauthenticated upstream build or
# modifying login items. Review the fork and build from source explicitly.
$ErrorActionPreference = "Stop"
throw @"
This hardened fork currently requires a reviewed source installation:

  git clone https://github.com/dingdinglz/clipaste.git
  cd clipaste
  cargo test --locked
  cargo install --path . --locked

See README.md and SECURITY.md. This script did not download a binary, change PATH,
modify login items, or start a clipboard service.
"@
