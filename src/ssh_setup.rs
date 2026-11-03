use crate::{common, security};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// All helpers fail closed on authentication, transport, or malformed-response
// errors. Only a successful `type: empty` response permits native fallback.
// Non-clipboard invocations still go directly to the real tool, with argv intact.
const HELPER_COMMON: &str = r#"
set +x
umask 077
CLIPASTE_URL='__CLIPASTE_URL__'
clipaste_die() { printf 'clipaste: %s\n' "$*" >&2; exit 1; }
clipaste_mode() {
    if [ "$(uname -s)" = Darwin ]; then stat -f '%Lp' "$1"; else stat -c '%a' "$1"; fi
}
clipaste_links() {
    if [ "$(uname -s)" = Darwin ]; then stat -f '%l' "$1"; else stat -c '%h' "$1"; fi
}
clipaste_size() {
    if [ "$(uname -s)" = Darwin ]; then stat -f '%z' "$1"; else stat -c '%s' "$1"; fi
}
# Check every component, not just the final path (including dangling links).
clipaste_check_chain() {
    local p="$1"
    case "$p" in /*) ;; *) clipaste_die 'an absolute HOME/config/cache path is required';; esac
    while [ "$p" != / ]; do
        [ ! -L "$p" ] || clipaste_die "refusing symlink: $p"
        if [ -e "$p" ]; then
            [ -d "$p" ] || clipaste_die "not a directory: $p"
            local mode
            mode=$(clipaste_mode "$p")
            # Shared sticky ancestors (/tmp) are safe; writable non-sticky
            # parents would let another user replace a private child directory.
            (( (8#$mode & 0022) == 0 || (8#$mode & 01000) != 0 )) || clipaste_die "unsafe writable directory: $p"
        fi
        p="${p%/*}"; [ -n "$p" ] || p=/
    done
}
clipaste_private_dir() {
    clipaste_check_chain "$1"
    if [ ! -e "$1" ]; then mkdir -p "$1" || clipaste_die 'cannot create private directory'; fi
    [ -d "$1" ] && [ -O "$1" ] && [ "$(clipaste_mode "$1")" = 700 ] || clipaste_die "directory must be owned by you and mode 0700: $1"
}
clipaste_private_file() {
    [ ! -L "$1" ] && [ -f "$1" ] && [ -O "$1" ] &&
        [ "$(clipaste_mode "$1")" = 600 ] && [ "$(clipaste_links "$1")" = 1 ] || clipaste_die "unsafe private file: $1"
}
clipaste_read_token() {
    clipaste_private_file "$1"
    local size
    size=$(clipaste_size "$1")
    [ "$size" = 64 ] || [ "$size" = 65 ] || clipaste_die 'invalid token length'
    clipaste_token=$(cat "$1") || clipaste_die 'cannot read token'
    export -n clipaste_token
    [[ "$clipaste_token" =~ ^[0-9a-f]{64}$ ]] || clipaste_die 'invalid token; rerun setup'
}
clipaste_load_token() {
    local d="${XDG_CONFIG_HOME:-$HOME/.config}/clipaste"
    clipaste_check_chain "$d"
    [ -d "$d" ] && [ -O "$d" ] && [ "$(clipaste_mode "$d")" = 700 ] || clipaste_die 'missing or unsafe token directory; rerun setup'
    clipaste_read_token "$d/token"
}
clipaste_curl() {
    printf 'header = "Authorization: Bearer %s"\n' "$clipaste_token" |
        curl -q --config - --noproxy '*' --connect-timeout 2 --max-time 10 --fail --silent "$@"
}
clipaste_type() {
    clipaste_load_token
    local body
    body=$(clipaste_curl "$CLIPASTE_URL/clipboard/type") || clipaste_die 'authentication or transport failed (no native fallback)'
    body=$(printf '%s' "$body" | tr -d '[:space:]')
    case "$body" in
        '{"type":"image","format":"png"}') clipaste_kind=image ;;
        '{"type":"empty"}') clipaste_kind=empty ;;
        *) clipaste_die 'invalid clipboard response (no native fallback)' ;;
    esac
}
clipaste_tmp=''
clipaste_reservation=''
clipaste_cleanup() {
    if [ -n "$clipaste_tmp" ]; then rm -f "$clipaste_tmp"; fi
    if [ -n "$clipaste_reservation" ]; then rm -f "$clipaste_reservation"; fi
}
trap clipaste_cleanup EXIT
trap 'exit 1' HUP INT TERM
clipaste_fetch() {
    local cache="${XDG_CACHE_HOME:-$HOME/.cache}/clipaste"
    clipaste_private_dir "$cache"
    clipaste_private_dir "$cache/paste"
    # This directory is dedicated to our private managed downloads. Do not
    # traverse directories, links, or remove other names/owners/permissions.
    find "$cache/paste/." ! -name . -prune -type f -name 'clipaste-image.*' -user "$(id -u)" -links 1 -perm 0600 -mmin +59 -exec rm -f {} + || clipaste_die 'cannot expire managed images'
    # BSD mktemp appends random characters if Xs are followed by .png. Reserve
    # a portable template first, then publish a .png name without overwriting.
    clipaste_tmp=$(mktemp "$cache/paste/clipaste-image.XXXXXXXX") || clipaste_die 'mktemp failed'
    ln "$clipaste_tmp" "$clipaste_tmp.png" || clipaste_die 'cannot reserve PNG filename'
    clipaste_reservation="$clipaste_tmp"
    clipaste_tmp="$clipaste_tmp.png"
    rm -f "$clipaste_reservation" || clipaste_die 'cannot release filename reservation'
    clipaste_reservation=''
    chmod 600 "$clipaste_tmp" || clipaste_die 'cannot secure image'
    clipaste_curl -o "$clipaste_tmp" "$CLIPASTE_URL/clipboard/image" && [ -s "$clipaste_tmp" ] || clipaste_die 'image fetch failed (no native fallback)'
}
clipaste_native() {
    local tool="$1" rest="$PATH" dir candidate
    shift
    while :; do
        dir=${rest%%:*}
        # Exclude the shim directory in *every* PATH position, including last.
        if [ -n "$dir" ] && [ "$dir" != "$HOME/.local/bin" ]; then
            candidate="$dir/$tool"
            if [ -x "$candidate" ] && [ ! -d "$candidate" ] && ! [ "$candidate" -ef "$0" ]; then
                exec "$candidate" "$@"
            fi
        fi
        case "$rest" in *:*) rest=${rest#*:} ;; *) break ;; esac
    done
    clipaste_die "$tool not found outside the shim directory"
}
"#;

const XCLIP_BODY: &str = r#"
case "$*" in
    *"-selection clipboard"*"-t TARGETS"*"-o"*|*"-sel clip"*"-t TARGETS"*"-o"*)
        clipaste_type
        if [ "$clipaste_kind" = image ]; then printf 'TARGETS\nimage/png\n'; exit 0; fi
        ;;
    *"-selection clipboard"*"-t image/png"*"-o"*|*"-sel clip"*"-t image/png"*"-o"*)
        clipaste_type
        if [ "$clipaste_kind" = image ]; then clipaste_fetch; cat "$clipaste_tmp"; exit $?; fi
        ;;
esac
clipaste_native xclip "$@"
"#;
const WL_PASTE_BODY: &str = r#"
case "$*" in
    *"--list-types"*)
        clipaste_type
        if [ "$clipaste_kind" = image ]; then printf 'image/png\n'; exit 0; fi
        ;;
    *"--type image/"*|*"-t image/"*)
        clipaste_type
        if [ "$clipaste_kind" = image ]; then clipaste_fetch; cat "$clipaste_tmp"; exit $?; fi
        ;;
esac
clipaste_native wl-paste "$@"
"#;
const PASTE_BODY: &str = r#"
clipaste_type
[ "$clipaste_kind" = image ] || clipaste_die 'no image on clipboard; take a screenshot first'
clipaste_fetch
printf '%s\n' "$clipaste_tmp"
# The printed file stays usable for one hour; subsequent helper calls expire it.
clipaste_tmp=''
"#;

fn helper_script(name: &str, url: &str) -> String {
    let body = match name {
        "xclip" => XCLIP_BODY,
        "wl-paste" => WL_PASTE_BODY,
        "clipaste-paste" => PASTE_BODY,
        _ => unreachable!("internal helper name"),
    };
    format!(
        "#!/bin/bash\n# clipaste managed helper v2: {name}\n{}{body}",
        HELPER_COMMON.replace("__CLIPASTE_URL__", url)
    )
}

// Shared local/remote installer: first preflight *all* destinations, then stage
// private files and rename them. No installed executable contains a secret.
const INSTALL_PREFLIGHT: &str = r#"
set -eu
export -n clipaste_token
[[ "$clipaste_token" =~ ^[0-9a-f]{64}$ ]] || clipaste_die 'invalid setup token'
OS=$(uname -s)
bin="$HOME/.local/bin"
config="${XDG_CONFIG_HOME:-$HOME/.config}/clipaste"
clipaste_check_chain "$bin"
clipaste_check_chain "$config"
# A same-user process can edit its own scripts. Only exact leading markers on
# owned, non-writable-by-others regular files count, never a substring comment.
clipaste_owned_file() {
    [ ! -L "$1" ] && [ -f "$1" ] && [ -O "$1" ] && [ "$(clipaste_links "$1")" = 1 ] || clipaste_die "refusing unsafe file: $1"
    local mode
    mode=$(clipaste_mode "$1")
    (( (8#$mode & 0022) == 0 )) || clipaste_die "file writable by others: $1"
}
clipaste_safe_dir() {
    if [ -e "$1" ]; then
        [ -O "$1" ] || clipaste_die "directory not owned by you: $1"
        local mode
        mode=$(clipaste_mode "$1")
        (( (8#$mode & 0022) == 0 )) || clipaste_die "directory writable by others: $1"
    fi
}
clipaste_safe_dir "$HOME"
clipaste_safe_dir "$HOME/.local"
clipaste_safe_dir "$bin"
clipaste_safe_dir "${XDG_CONFIG_HOME:-$HOME/.config}"
if [ -e "$config" ]; then
    [ -O "$config" ] && [ "$(clipaste_mode "$config")" = 700 ] || clipaste_die 'unsafe token directory'
fi
if [ -e "$config/token" ] || [ -L "$config/token" ]; then
    # Subshell validates the existing credential without replacing the newly
    # supplied setup token. Never overwrite an arbitrary file named token.
    ( clipaste_read_token "$config/token" )
fi
names=(clipaste-paste)
if [ "$OS" = Linux ]; then names+=(xclip wl-paste); fi
for name in "${names[@]}"; do
    dest="$bin/$name"
    if [ -e "$dest" ] || [ -L "$dest" ]; then
        clipaste_owned_file "$dest"
        header=$(head -n 2 "$dest")
        expected=$(printf '#!/bin/bash\n# clipaste managed helper v2: %s' "$name")
        if [ "$header" != "$expected" ]; then
            # Exact upstream headers allow upgrading the original owned shims.
            case "$name" in
                xclip) legacy=$(printf '#!/bin/bash\n# clipaste xclip shim — intercepts xclip calls and fetches images from clipaste\n# Installed by: clipaste wsl-setup') ;;
                wl-paste) legacy=$(printf '#!/bin/bash\n# clipaste wl-paste shim — for Wayland environments\n# Installed by: clipaste wsl-setup') ;;
                clipaste-paste) legacy=$(printf '#!/bin/bash\n# clipaste-paste — fetch the current clipboard image from your LOCAL machine\n# (through the clipaste SSH tunnel / WSL bridge) into a real file on THIS host,') ;;
            esac
            [ "$(head -n 3 "$dest")" = "$legacy" ] || clipaste_die "refusing unknown helper: $dest (move it aside manually)"
        fi
    fi
done
rcs=()
# Merely being present is insufficient: native tools earlier in PATH would
# bypass the bridge. Future shells must put the managed directory first.
if [ "${PATH%%:*}" != "$HOME/.local/bin" ]; then
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [ -e "$rc" ] || [ -L "$rc" ]; then
            clipaste_owned_file "$rc"
            rcs+=("$rc")
        fi
    done
    if [ "${#rcs[@]}" = 0 ]; then
        case "${SHELL:-}" in */zsh|zsh) rcs+=("$HOME/.zshrc") ;; *) rcs+=("$HOME/.bashrc") ;; esac
    fi
fi
# No writes above this point.
mkdir -p "$bin"
clipaste_private_dir "$config"
stage=''
token_stage=''
rc_stage=''
clipaste_install_cleanup() {
    [ -z "$stage" ] || rm -rf "$stage"
    [ -z "$token_stage" ] || rm -f "$token_stage"
    [ -z "$rc_stage" ] || rm -f "$rc_stage"
    :
}
trap clipaste_install_cleanup EXIT
trap 'exit 1' HUP INT TERM
stage=$(mktemp -d "$bin/.clipaste-setup.XXXXXXXX")
chmod 700 "$stage"
token_stage=$(mktemp "$config/.token.XXXXXXXX")
printf '%s\n' "$clipaste_token" > "$token_stage"
chmod 600 "$token_stage"
unset clipaste_token
"#;

const INSTALL_FINISH: &str = r#"
for name in "${names[@]}"; do chmod 700 "$stage/$name"; done
mv -f "$token_stage" "$config/token"
token_stage=''
for name in "${names[@]}"; do mv -f "$stage/$name" "$bin/$name"; done
for rc in "${rcs[@]}"; do
    if [ -f "$rc" ] && grep -Fqx 'export PATH="$HOME/.local/bin:$PATH"' "$rc"; then continue; fi
    rc_stage=$(mktemp "$rc.clipaste.XXXXXXXX")
    if [ -f "$rc" ]; then cat "$rc" > "$rc_stage"; fi
    printf '\n# clipaste PATH\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$rc_stage"
    chmod 600 "$rc_stage"
    mv -f "$rc_stage" "$rc"
    rc_stage=''
done
printf 'CLIPASTE_OS=%s\nOK\n' "$OS"
"#;

fn build_remote_setup_script(url: &str, token: &str) -> Result<String, String> {
    validate_base_url(url)?;
    if !security::valid_token(token) {
        return Err("invalid setup token".into());
    }
    // SSH stdin only. set +x precedes the secret even under `bash -x`.
    let mut script = format!(
        "set +x\nunset clipaste_token\nread -r clipaste_token <<'CLIPASTE_TOKEN_EOF'\n{token}\nCLIPASTE_TOKEN_EOF\n"
    );
    script.push_str(&HELPER_COMMON.replace("__CLIPASTE_URL__", url));
    script.push_str(INSTALL_PREFLIGHT);
    for name in ["clipaste-paste", "xclip", "wl-paste"] {
        script.push_str(&format!(
            "cat > \"$stage/{name}\" <<'CLIPASTE_HELPER_EOF'\n{}CLIPASTE_HELPER_EOF\n",
            helper_script(name, url)
        ));
    }
    script.push_str(INSTALL_FINISH);
    Ok(script)
}

fn ssh_port_args(port: Option<u16>) -> Vec<String> {
    port.map(|p| vec!["-p".into(), p.to_string()])
        .unwrap_or_default()
}

fn run_payload(mut command: Command, script: &str, token: &str) -> Result<String, String> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start installer: {e}"))?;
    let write_result = child
        .stdin
        .take()
        .ok_or("installer stdin unavailable")?
        .write_all(script.as_bytes());
    let output = child
        .wait_with_output()
        .map_err(|e| format!("waiting for installer: {e}"))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).replace(token, "[REDACTED]");
        return Err(format!(
            "installer failed; it may have partially installed files: {}",
            err.trim()
        ));
    }
    write_result.map_err(|e| format!("sending setup payload: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).replace(token, "[REDACTED]");
    Ok(stdout
        .lines()
        .find_map(|s| s.strip_prefix("CLIPASTE_OS="))
        .unwrap_or("Unknown")
        .to_owned())
}

fn install_shims_via_ssh(
    host: &str,
    url: &str,
    port: Option<u16>,
    token: &str,
) -> Result<String, String> {
    validate_ssh_host(host)?;
    let script = build_remote_setup_script(url, token)?;
    let mut command = Command::new("ssh");
    command
        .args(ssh_port_args(port))
        .args(["-o", "ClearAllForwardings=yes"])
        .arg("--")
        .arg(host)
        .arg("bash -s");
    run_payload(command, &script, token)
}

fn install_shims_locally(url: &str, token: &str) -> Result<(), String> {
    let script = build_remote_setup_script(url, token)?;
    run_payload(Command::new("bash"), &script, token).map(|_| ())
}

fn verify_auth(url: &str, token: &str) -> Result<(), String> {
    if !security::valid_token(token) {
        return Err("invalid token".into());
    }
    match security::http_get_authenticated(&format!("{url}/clipboard/type"), token) {
        Some(body) if body.contains("\"type\":\"image\"") || body.contains("\"type\":\"empty\"") => Ok(()),
        _ => Err("authenticated /clipboard/type check failed; check the daemon and token (nothing installed)".into()),
    }
}

pub fn run_ssh(host: &str, ssh_port: Option<u16>) {
    if let Err(e) = setup_ssh(host, ssh_port) {
        eprintln!("clipaste ssh-setup: {e}");
        std::process::exit(1);
    }
}

fn setup_ssh(host: &str, port: Option<u16>) -> Result<(), String> {
    validate_ssh_host(host)?;
    if port == Some(0) {
        return Err("SSH port must not be zero".into());
    }
    let token = security::load_token()
        .map_err(|e| format!("cannot load local token: {e}; start the daemon first"))?;
    let url = format!("http://127.0.0.1:{}", common::DEFAULT_PORT);
    verify_auth(&url, &token)?;
    // Read errors, malformed configs, and unsafe destinations fail before SSH.
    let plan = prepare_ssh_config(&dirs_home()?, host, port)?;
    let remote_os = install_shims_via_ssh(host, &url, port, &token)?;
    apply_ssh_config(plan).map_err(|e| {
        format!(
            "remote helpers installed, but SSH config was NOT updated: {e}; fix it and rerun setup"
        )
    })?;
    println!("Setup complete ({remote_os}). Open a NEW session: ssh {host}");
    println!("Then run clipaste doctor; use clipaste-paste for an image path.");
    println!("Authentication/transport failures never fall back to the native clipboard; an empty clipboard may.");
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostCandidate {
    ip: String,
    source: &'static str,
}
const MIRRORED_LOOPBACK: &str = "mirrored-mode loopback";
const RESOLV_NAMESERVER: &str = "/etc/resolv.conf nameserver";
const DEFAULT_GATEWAY: &str = "default gateway";

fn wsl_host_candidates(
    mode: Option<&str>,
    nameserver: Option<String>,
    gateway: Option<String>,
) -> Vec<HostCandidate> {
    let loopback = HostCandidate {
        ip: "127.0.0.1".into(),
        source: MIRRORED_LOOPBACK,
    };
    let mirrored = mode.is_some_and(|m| m.eq_ignore_ascii_case("mirrored"));
    let mut out = Vec::new();
    if mirrored {
        out.push(loopback.clone());
    }
    if let Some(ip) = nameserver {
        out.push(HostCandidate {
            ip,
            source: RESOLV_NAMESERVER,
        });
    }
    if let Some(ip) = gateway {
        out.push(HostCandidate {
            ip,
            source: DEFAULT_GATEWAY,
        });
    }
    if !mirrored {
        out.push(loopback);
    }
    let mut seen = Vec::new();
    out.retain(|c| {
        if c.ip.parse::<IpAddr>().is_err() || seen.contains(&c.ip) {
            false
        } else {
            seen.push(c.ip.clone());
            true
        }
    });
    out
}

fn ip_base_url(host: &str) -> Result<String, String> {
    let ip: IpAddr = host.parse().map_err(|_| {
        "--host must be a literal IPv4 or IPv6 address (no URL, hostname, or userinfo)".to_string()
    })?;
    Ok(match ip {
        IpAddr::V4(ip) => format!("http://{ip}:{}", common::DEFAULT_PORT),
        IpAddr::V6(ip) => format!("http://[{ip}]:{}", common::DEFAULT_PORT),
    })
}

fn validate_base_url(url: &str) -> Result<(), String> {
    let authority = url
        .strip_prefix("http://")
        .and_then(|s| s.strip_suffix(&format!(":{}", common::DEFAULT_PORT)))
        .ok_or("invalid helper URL")?;
    let host = authority
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(authority);
    if ip_base_url(host)? != url {
        return Err("helper URL must contain a canonical literal IP address".into());
    }
    Ok(())
}

pub fn run_wsl(host: Option<String>, token_file: Option<&Path>) {
    if let Err(e) = setup_wsl(host, token_file) {
        eprintln!("clipaste wsl-setup: {e}");
        std::process::exit(1);
    }
}

fn setup_wsl(host: Option<String>, token_file: Option<&Path>) -> Result<(), String> {
    // Validate explicit input before even making a public discovery request.
    let explicit_url = host.as_deref().map(ip_base_url).transpose()?;
    let token = match token_file {
        Some(path) => security::read_token(path),
        None => security::load_token(),
    }.map_err(|e| format!("cannot read token: {e}; first setup requires --token-file PATH containing the Windows daemon token"))?;
    let url = if let Some(url) = explicit_url {
        if !check_health(&url) {
            return Err(format!("no authenticated-capable clipaste daemon at {url}"));
        }
        url
    } else {
        let mode = wsl_networking_mode();
        let candidates = wsl_host_candidates(
            mode.as_deref(),
            read_resolv_nameserver(),
            read_default_gateway(),
        );
        let found = candidates
            .iter()
            .filter_map(|c| ip_base_url(&c.ip).ok())
            .find(|url| check_health(url));
        match found {
            Some(url) => url,
            None => {
                print_wsl_failure_help(&candidates, mode.as_deref());
                return Err("no Windows clipaste daemon found; nothing installed".into());
            }
        }
    };
    verify_auth(&url, &token)?;
    install_shims_locally(&url, &token)?;
    println!("WSL helpers installed. Open a new terminal, then run clipaste doctor.");
    println!("Use clipaste-paste for an image path. Managed downloads expire after one hour on the next helper download.");
    Ok(())
}

fn print_wsl_failure_help(candidates: &[HostCandidate], mode: Option<&str>) {
    eprintln!("No clipaste daemon answered. Tried:");
    for c in candidates {
        eprintln!("  {} ({})", c.ip, c.source);
    }
    eprintln!("WSL networking mode: {}", mode.unwrap_or("unknown"));
    eprintln!("Start clipaste.exe on Windows. NAT cannot reach its loopback listener; use mirrored networking in %USERPROFILE%\\.wslconfig, then wsl --shutdown.");
    eprintln!(
        "You may select a literal IP with --host; first setup also requires --token-file PATH."
    );
}

fn check_health(url: &str) -> bool {
    let out = Command::new("curl")
        .args([
            "-q",
            "--noproxy",
            "*",
            "--connect-timeout",
            "2",
            "--max-time",
            "10",
            "-fsS",
            &format!("{url}/health"),
        ])
        .output();
    matches!(out, Ok(o) if o.status.success() && is_clipaste_health_body(&String::from_utf8_lossy(&o.stdout)))
}
fn is_clipaste_health_body(body: &str) -> bool {
    let body: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    body.contains("\"status\":\"ok\"") && body.contains("\"auth\":\"bearer\"")
}
fn wsl_networking_mode() -> Option<String> {
    let out = Command::new("wslinfo")
        .arg("--networking-mode")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let mode = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
    if mode.is_empty() {
        None
    } else {
        Some(mode)
    }
}
fn read_resolv_nameserver() -> Option<String> {
    parse_resolv_nameserver(&std::fs::read_to_string("/etc/resolv.conf").ok()?)
}
fn parse_resolv_nameserver(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != "nameserver" {
            return None;
        }
        Some(fields.next()?.parse::<IpAddr>().ok()?.to_string())
    })
}
fn read_default_gateway() -> Option<String> {
    if let Ok(out) = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        if out.status.success() {
            if let Some(gw) = parse_ip_route_default(&String::from_utf8_lossy(&out.stdout)) {
                return Some(gw);
            }
        }
    }
    parse_proc_net_route(&std::fs::read_to_string("/proc/net/route").ok()?)
}
fn parse_ip_route_default(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != "default" {
            return None;
        }
        let mut fields = fields.skip_while(|v| *v != "via");
        fields.next()?;
        Some(fields.next()?.parse::<IpAddr>().ok()?.to_string())
    })
}
fn parse_proc_net_route(content: &str) -> Option<String> {
    content.lines().skip(1).find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 3 || fields[1] != "00000000" {
            return None;
        }
        let n = u32::from_str_radix(fields[2], 16).ok()?;
        if n == 0 {
            return None;
        }
        Some(std::net::Ipv4Addr::from(n.to_le_bytes()).to_string())
    })
}

// Only our delimited blocks are parsed. Arbitrary Host/Match/Include syntax and
// bytes are left alone; a Host * line restores context before the original.
fn validate_ssh_host(host: &str) -> Result<&str, String> {
    let mut pieces = host.split('@');
    let first = pieces.next().unwrap_or("");
    let second = pieces.next();
    if pieces.next().is_some() {
        return Err("invalid SSH target".into());
    }
    let hostname = second.unwrap_or(first);
    let valid = |s: &str| {
        !s.is_empty()
            && !s.starts_with('-')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    };
    if !valid(first) || !valid(hostname) {
        return Err("SSH target must be [user@]literal-host using only letters, digits, dots, underscores, and hyphens".into());
    }
    Ok(hostname)
}

fn managed_block(host: &str, port: Option<u16>) -> String {
    let mut block = format!("# BEGIN clipaste {host}\nHost {host}\n    RemoteForward 127.0.0.1:{0} 127.0.0.1:{0}\n    ExitOnForwardFailure yes\n", common::DEFAULT_PORT);
    if let Some(port) = port {
        block.push_str(&format!("    Port {port}\n"));
    }
    block.push_str(&format!("# END clipaste {host}\nHost *\n"));
    block
}

fn remove_managed_blocks(existing: &str, target: Option<&str>) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = existing;
    while !rest.is_empty() {
        let end = rest.find('\n').map(|n| n + 1).unwrap_or(rest.len());
        let line = &rest[..end];
        if let Some(host) = line
            .strip_prefix("# BEGIN clipaste ")
            .and_then(|s| s.strip_suffix('\n'))
        {
            validate_ssh_host(host)?;
            if host.contains('@') {
                return Err("invalid managed Host block".into());
            }
            let marker = format!("# END clipaste {host}\nHost *\n");
            let n = rest
                .find(&marker)
                .ok_or("unterminated clipaste managed block")?
                + marker.len();
            let block = &rest[..n];
            let port = block.lines().find_map(|l| {
                l.strip_prefix("    Port ")
                    .and_then(|p| p.parse::<u16>().ok())
            });
            if block != managed_block(host, port) {
                return Err("modified clipaste managed block; resolve it manually".into());
            }
            if target.is_some_and(|t| t != host) {
                out.push_str(block);
            }
            rest = &rest[n..];
        } else {
            out.push_str(line);
            rest = &rest[end..];
        }
    }
    Ok(out)
}

fn build_ssh_config(existing: &str, hostname: &str, port: Option<u16>) -> Result<String, String> {
    validate_ssh_host(hostname)?;
    if hostname.contains('@') || port == Some(0) {
        return Err("invalid SSH host pattern or port".into());
    }
    // Conservative, context-free conflict detection: never guess which Host or
    // Match a preexisting forwarding directive applies to. Includes stay intact;
    // ExitOnForwardFailure prevents a hidden included conflict being silent.
    let unmanaged = remove_managed_blocks(existing, None)?;
    for line in unmanaged.lines() {
        let line = line.trim_start();
        if line.starts_with('#') {
            continue;
        }
        let mut fields = line
            .split(|c: char| c.is_ascii_whitespace() || c == '=')
            .filter(|s| !s.is_empty());
        if fields
            .next()
            .is_some_and(|s| s.eq_ignore_ascii_case("RemoteForward"))
        {
            let listen = fields.next().ok_or("malformed unmanaged RemoteForward")?;
            if listen.trim_matches('"').rsplit(':').next()
                == Some(&common::DEFAULT_PORT.to_string())
            {
                return Err(
                    "unmanaged RemoteForward uses clipaste's port; remove/resolve it before setup"
                        .into(),
                );
            }
        }
    }
    let remaining = remove_managed_blocks(existing, Some(hostname))?;
    Ok(format!("{}{remaining}", managed_block(hostname, port)))
}

struct ConfigPlan {
    path: PathBuf,
    original: Option<Vec<u8>>,
    updated: Vec<u8>,
}

fn dirs_home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or("HOME/USERPROFILE must be an absolute path".into())
}

fn check_directory_chain(path: &Path) -> Result<(), String> {
    for p in path.ancestors() {
        match std::fs::symlink_metadata(p) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                return Err(format!("unsafe directory: {}", p.display()))
            }
            Ok(meta) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0 {
                        return Err(format!("unsafe writable directory: {}", p.display()));
                    }
                }
                #[cfg(not(unix))]
                let _ = meta;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(format!("inspect {}: {e}", p.display())),
        }
    }
    Ok(())
}

fn read_owned_file(path: &Path, private: bool) -> Result<Option<Vec<u8>>, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("inspect {}: {e}", path.display())),
    };
    validate_file_metadata(path, &metadata, private)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|e| format!("inspect open {}: {e}", path.display()))?;
    validate_file_metadata(path, &opened, private)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(Some(bytes))
}

fn validate_file_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    private: bool,
) -> Result<(), String> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("refusing nonregular file: {}", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
            || (private && metadata.mode() & 0o777 != 0o600)
        {
            return Err(format!(
                "unsafe ownership, links, or permissions: {}",
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    Ok(())
}

fn backup_path(config: &Path) -> PathBuf {
    config.with_file_name("config.clipaste.bak")
}

fn prepare_ssh_config(home: &Path, host: &str, port: Option<u16>) -> Result<ConfigPlan, String> {
    let hostname = validate_ssh_host(host)?;
    let directory = home.join(".ssh");
    check_directory_chain(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let parent = if directory.exists() { &directory } else { home };
        let meta =
            std::fs::metadata(parent).map_err(|e| format!("inspect {}: {e}", parent.display()))?;
        if meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o022 != 0
            || meta.mode() & 0o300 != 0o300
        {
            return Err("SSH config parent must be owned by you, writable/searchable, and not writable by others".into());
        }
    }
    let path = directory.join("config");
    let original = read_owned_file(&path, false)?;
    let text = std::str::from_utf8(original.as_deref().unwrap_or(b""))
        .map_err(|_| "SSH config is not UTF-8; refusing to rewrite it")?;
    let updated = build_ssh_config(text, hostname, port)?.into_bytes();
    // Refuse an unsafe backup *before* deploying anything remotely.
    read_owned_file(&backup_path(&path), true)?;
    Ok(ConfigPlan {
        path,
        original,
        updated,
    })
}

fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn atomic_private_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|e| format!("temporary file randomness: {e}"))?;
    let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let stage = path.with_file_name(format!(".clipaste-config-{suffix}"));
    let mut created = false;
    let result = (|| {
        let mut file = create_private(&stage)?;
        created = true;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&stage, path)
    })();
    if result.is_err() && created {
        let _ = std::fs::remove_file(&stage);
    }
    result.map_err(|e| format!("atomic write {}: {e}", path.display()))
}

fn apply_ssh_config(plan: ConfigPlan) -> Result<(), String> {
    check_directory_chain(plan.path.parent().ok_or("missing config parent")?)?;
    if read_owned_file(&plan.path, false)? != plan.original {
        return Err(
            "SSH config changed during setup; refusing to overwrite concurrent edits".into(),
        );
    }
    if plan.original.as_deref() == Some(plan.updated.as_slice()) {
        return Ok(());
    }
    let directory = plan.path.parent().ok_or("missing config parent")?;
    if !directory.exists() {
        #[allow(unused_mut)]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(directory)
            .map_err(|e| format!("create ~/.ssh: {e}"))?;
    }
    let backup = backup_path(&plan.path);
    if let Some(original) = plan.original {
        if read_owned_file(&backup, true)?.is_none() {
            let mut file =
                create_private(&backup).map_err(|e| format!("create config backup: {e}"))?;
            if let Err(e) = file.write_all(&original).and_then(|_| file.sync_all()) {
                drop(file);
                let _ = std::fs::remove_file(&backup);
                return Err(format!("write config backup (config unchanged): {e}"));
            }
        }
    }
    atomic_private_write(&plan.path, &plan.updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::sync::atomic::{AtomicUsize, Ordering};
    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const URL: &str = "http://127.0.0.1:18340";
    #[cfg(unix)]
    struct TempHome(PathBuf);
    #[cfg(unix)]
    impl TempHome {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "clipaste-setup-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }
        fn command(&self) -> Command {
            let mut command = Command::new("/bin/bash");
            command
                .env_clear()
                .env("HOME", &self.0)
                .env("SHELL", "/bin/zsh")
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
            command
        }
        fn run(&self, script: &str) -> std::process::Output {
            let mut command = self.command();
            command.arg("-s");
            shell_output(command, script)
        }
    }
    #[cfg(unix)]
    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[cfg(unix)]
    fn shell_output(mut command: Command, script: &str) -> std::process::Output {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
    #[cfg(unix)]
    fn success(output: std::process::Output) {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn first_use_keeps_target_and_original_bytes() {
        let original = "# RemoteForward 18340 127.0.0.1:18340\r\nHOST\tprod\n\tUser me\nMatch host prod\n\tCompression yes\nInclude ~/.ssh/config.d/*\nHost *\n Port 22";
        let hostname = validate_ssh_host("alice@prod").unwrap();
        let updated = build_ssh_config(original, hostname, Some(2222)).unwrap();
        assert!(updated.starts_with("# BEGIN clipaste prod\nHost prod\n"));
        assert!(updated.ends_with(original));
        assert!(!updated.contains("Host clipaste-"));
        assert!(updated.contains("ExitOnForwardFailure yes\n    Port 2222\n"));
        assert_eq!(
            build_ssh_config(&updated, hostname, Some(2222)).unwrap(),
            updated
        );
    }
    #[test]
    fn managed_update_keeps_other_blocks() {
        let a = build_ssh_config("Host *\n User me\n", "one", None).unwrap();
        let b = build_ssh_config(&a, "two", None).unwrap();
        let c = build_ssh_config(&b, "one", Some(2222)).unwrap();
        assert!(c.contains(&managed_block("two", None)));
        assert_eq!(c.matches("# BEGIN clipaste one\n").count(), 1);
        assert!(build_ssh_config(
            "Host prod\n REMOTEFORWARD\t127.0.0.1:18340 localhost:18340\n",
            "prod",
            None
        )
        .is_err());
        assert!(build_ssh_config("# BEGIN clipaste prod\nHost evil\n", "prod", None).is_err());
    }
    #[test]
    fn reject_config_and_shell_injection() {
        for host in [
            "-oProxyCommand=bad",
            "a\nb",
            "a b",
            "*@host",
            "a@b@host",
            "a!b",
            "[host]",
            "a;bad",
            "a#b",
            "a\\b",
            "a%h",
            "",
        ] {
            assert!(validate_ssh_host(host).is_err(), "{host:?}");
        }
        for host in [
            "127.0.0.1;touch /tmp/bad",
            "localhost",
            "user@127.0.0.1",
            "127.0.0.1/path",
            "[::1]",
            "127.0.0.1\n",
        ] {
            assert!(ip_base_url(host).is_err());
        }
        assert_eq!(ip_base_url("::1").unwrap(), "http://[::1]:18340");
        assert!(build_remote_setup_script("http://evil:18340", TOKEN).is_err());
        assert!(build_remote_setup_script(URL, "bad").is_err());
        assert_eq!(ssh_port_args(Some(2222)), ["-p", "2222"]);
    }
    #[cfg(unix)]
    #[test]
    fn generated_scripts_parse() {
        let home = TempHome::new();
        for script in [
            build_remote_setup_script(URL, TOKEN).unwrap(),
            helper_script("xclip", URL),
            helper_script("wl-paste", URL),
            helper_script("clipaste-paste", URL),
        ] {
            let mut command = home.command();
            command.arg("-n");
            success(shell_output(command, &script));
        }
    }
    #[cfg(unix)]
    #[test]
    fn installer_is_private_idempotent_and_secret_free() {
        use std::os::unix::fs::PermissionsExt;
        let home = TempHome::new();
        let script = build_remote_setup_script(URL, TOKEN).unwrap();
        success(home.run(&script));
        let helper = home.0.join(".local/bin/clipaste-paste");
        assert_eq!(
            std::fs::metadata(&helper).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(!std::fs::read_to_string(helper).unwrap().contains(TOKEN));
        for path in [".config/clipaste", ".config/clipaste/token"] {
            let mode = std::fs::metadata(home.0.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode,
                if path.ends_with("token") {
                    0o600
                } else {
                    0o700
                }
            );
        }
        success(home.run(&script));
        let rc = std::fs::read_to_string(home.0.join(".zshrc")).unwrap();
        assert_eq!(rc.matches("# clipaste PATH").count(), 1);
        assert_eq!(
            std::fs::read_dir(home.0.join(".local/bin"))
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().starts_with(".clipaste-"))
                .count(),
            0
        );
    }
    #[cfg(unix)]
    #[test]
    fn installer_prepends_path_when_bin_is_last_but_not_when_already_first() {
        for already_first in [false, true] {
            let home = TempHome::new();
            let bin = home.0.join(".local/bin").display().to_string();
            let path = if already_first {
                format!("{bin}:/usr/bin:/bin")
            } else {
                format!("/usr/bin:/bin:{bin}")
            };
            let mut command = home.command();
            command.env("PATH", &path);
            let script = build_remote_setup_script(URL, TOKEN).unwrap();
            success(shell_output(command, &script));
            let rc = home.0.join(".zshrc");
            if already_first {
                assert!(
                    !rc.exists(),
                    "PATH already starts with the managed bin; no rc change needed"
                );
            } else {
                let content = std::fs::read_to_string(&rc).unwrap();
                assert!(content.contains("export PATH=\"$HOME/.local/bin:$PATH\""));
                let mut command = home.command();
                command.env("PATH", path);
                success(shell_output(command, &script));
                assert_eq!(std::fs::read_to_string(rc).unwrap(), content);
            }
        }
    }
    #[cfg(unix)]
    #[test]
    fn installer_refuses_unknown_and_symlink_before_writes() {
        use std::os::unix::fs::symlink;
        for link in [false, true] {
            let home = TempHome::new();
            std::fs::create_dir_all(home.0.join(".local/bin")).unwrap();
            let target = home.0.join("foreign");
            std::fs::write(&target, "#!/bin/bash\n# random clipaste comment\n").unwrap();
            let helper = home.0.join(".local/bin/clipaste-paste");
            if link {
                symlink(&target, &helper).unwrap();
            } else {
                std::fs::copy(&target, &helper).unwrap();
            }
            assert!(!home
                .run(&build_remote_setup_script(URL, TOKEN).unwrap())
                .status
                .success());
            assert!(!home.0.join(".config/clipaste/token").exists());
            assert!(!home.0.join(".zshrc").exists());
            assert_eq!(
                std::fs::read_to_string(target).unwrap(),
                "#!/bin/bash\n# random clipaste comment\n"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn ssh_config_backup_idempotence_and_invalid_utf8() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let home = TempHome::new();
        std::fs::create_dir(home.0.join(".ssh")).unwrap();
        let path = home.0.join(".ssh/config");
        let original = b"HOST\tprod\n User alice\nMatch all\nInclude config.d/*\n";
        std::fs::write(&path, original).unwrap();
        apply_ssh_config(prepare_ssh_config(&home.0, "alice@prod", None).unwrap()).unwrap();
        let first = std::fs::read(&path).unwrap();
        assert_eq!(std::fs::read(backup_path(&path)).unwrap(), original);
        assert_eq!(
            std::fs::metadata(backup_path(&path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        apply_ssh_config(prepare_ssh_config(&home.0, "alice@prod", None).unwrap()).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), first);
        std::fs::write(&path, [0xff, 0xfe]).unwrap();
        assert!(prepare_ssh_config(&home.0, "prod", None).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), [0xff, 0xfe]);
        std::fs::remove_file(&path).unwrap();
        symlink(home.0.join("missing"), &path).unwrap();
        assert!(prepare_ssh_config(&home.0, "prod", None).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn unreadable_nonregular_and_concurrent_config_are_not_overwritten() {
        let home = TempHome::new();
        std::fs::create_dir(home.0.join(".ssh")).unwrap();
        let path = home.0.join(".ssh/config");
        std::fs::create_dir(&path).unwrap();
        assert!(prepare_ssh_config(&home.0, "prod", None).is_err());
        std::fs::remove_dir(&path).unwrap();
        let plan = prepare_ssh_config(&home.0, "prod", None).unwrap();
        std::fs::write(&path, "concurrent edit").unwrap();
        assert!(apply_ssh_config(plan).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "concurrent edit");
    }
    #[cfg(unix)]
    #[test]
    fn permission_errors_and_backup_symlinks_are_not_ignored() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let home = TempHome::new();
        let directory = home.0.join(".ssh");
        let path = directory.join("config");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(&path, "Host prod\n User me\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o0)).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(prepare_ssh_config(&home.0, "prod", None).is_err());
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(prepare_ssh_config(&home.0, "prod", None).is_err());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink(home.0.join("unrelated"), backup_path(&path)).unwrap();
        assert!(prepare_ssh_config(&home.0, "prod", None).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "Host prod\n User me\n"
        );
    }
    #[cfg(unix)]
    #[test]
    fn native_fallback_path_last_preserves_arguments_and_does_not_recurse() {
        use std::os::unix::fs::PermissionsExt;
        let home = TempHome::new();
        std::fs::create_dir_all(home.0.join(".local/bin")).unwrap();
        std::fs::create_dir(home.0.join("native")).unwrap();
        for tool in ["xclip", "wl-paste"] {
            let shim = home.0.join(".local/bin").join(tool);
            let real = home.0.join("native").join(tool);
            std::fs::write(&shim, helper_script(tool, URL)).unwrap();
            std::fs::write(&real, "#!/bin/bash\nprintf '<%s>\\n' \"$@\"\n").unwrap();
            for path in [&shim, &real] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            for position in [0, 1, 2] {
                let bin = home.0.join(".local/bin").display().to_string();
                let native = home.0.join("native").display().to_string();
                let mut parts = vec![native, "/usr/bin:/bin".into()];
                parts.insert(position, bin);
                let out = home
                    .command()
                    .arg(&shim)
                    .args(["argument with spaces", "*", ""])
                    .env("PATH", parts.join(":"))
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                assert_eq!(
                    String::from_utf8_lossy(&out.stdout),
                    "<argument with spaces>\n<*>\n<>\n"
                );
            }
            let out = home
                .command()
                .arg(&shim)
                .arg("native-only")
                .env("PATH", home.0.join(".local/bin"))
                .output()
                .unwrap();
            assert!(!out.status.success());
        }
    }
    #[cfg(unix)]
    fn fake_curl(home: &TempHome) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = home.0.join("fake-tools");
        std::fs::create_dir(&dir).unwrap();
        let curl = dir.join("curl");
        std::fs::write(
            &curl,
            r#"#!/bin/bash
printf '<%s>\n' "$@" > "$HOME/curl-argv"
cat > "$HOME/curl-stdin"
output=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) output="$2"; shift ;;
        */clipboard/type)
            case "${FAKE_TYPE:-image}" in
                fail) exit 22 ;;
                empty) printf '{"type":"empty"}' ;;
                malformed) printf 'bad response' ;;
                *) printf '{"type":"image","format":"png"}' ;;
            esac
            exit 0 ;;
        */clipboard/image)
            [ "${FAKE_IMAGE:-ok}" = ok ] || exit 22
            printf 'dummy PNG' > "$output"
            exit 0 ;;
    esac
    shift
done
exit 99
"#,
        )
        .unwrap();
        std::fs::set_permissions(curl, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    #[cfg(unix)]
    #[test]
    fn authenticated_helpers_fail_closed_and_expire_only_managed_downloads() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let home = TempHome::new();
        success(home.run(&build_remote_setup_script(URL, TOKEN).unwrap()));
        let fake = fake_curl(&home);
        let helper = home.0.join(".local/bin/clipaste-paste");
        let fake_path = format!("{}:/usr/bin:/bin", fake.display());
        let output = home
            .command()
            .arg(&helper)
            .env("PATH", &fake_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let image = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
        let cache = image.parent().unwrap();
        assert_eq!(
            std::fs::metadata(&image).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(cache).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let unrelated = cache.join("keep.png");
        std::fs::write(&unrelated, "keep").unwrap();
        let nested = cache.join("unrelated-directory");
        std::fs::create_dir(&nested).unwrap();
        let nested_file = nested.join("clipaste-image.old.png");
        std::fs::write(&nested_file, "keep nested content").unwrap();
        std::fs::set_permissions(&nested_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = cache.join("clipaste-image.link.png");
        symlink(&unrelated, &link).unwrap();
        success(
            Command::new("touch")
                .args(["-t", "200001010000"])
                .arg(&image)
                .arg(&unrelated)
                .arg(&nested_file)
                .output()
                .unwrap(),
        );
        let output = home
            .command()
            .arg(&helper)
            .env("PATH", &fake_path)
            .output()
            .unwrap();
        success(output);
        assert!(!image.exists());
        assert!(unrelated.exists());
        assert!(
            nested_file.exists(),
            "expiry must not descend into unrelated directories"
        );
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        let argv = std::fs::read_to_string(home.0.join("curl-argv")).unwrap();
        assert!(argv.starts_with("<-q>\n<--config>\n<->\n"));
        assert!(argv.contains("<--noproxy>\n<*>\n"));
        assert!(argv.contains("<--connect-timeout>\n<2>\n<--max-time>\n<10>\n"));
        assert!(!argv.contains(TOKEN));
        assert_eq!(
            std::fs::read_to_string(home.0.join("curl-stdin")).unwrap(),
            format!("header = \"Authorization: Bearer {TOKEN}\"\n")
        );
        let count = std::fs::read_dir(cache).unwrap().count();
        let output = home
            .command()
            .arg(&helper)
            .env("PATH", &fake_path)
            .env("FAKE_IMAGE", "fail")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(
            std::fs::read_dir(cache).unwrap().count(),
            count,
            "failed download leaked a temp file"
        );
        for tool in ["xclip", "wl-paste"] {
            let shim = home.0.join(".local/bin").join(tool);
            // Darwin only installs the generic helper, so stage shims explicitly.
            std::fs::write(&shim, helper_script(tool, URL)).unwrap();
            let native = fake.join(tool);
            std::fs::write(&native, "#!/bin/bash\nprintf 'native fallback'\n").unwrap();
            std::fs::set_permissions(&native, std::fs::Permissions::from_mode(0o700)).unwrap();
            let args = if tool == "xclip" {
                vec!["-selection", "clipboard", "-t", "TARGETS", "-o"]
            } else {
                vec!["--list-types"]
            };
            for kind in ["fail", "malformed", "empty"] {
                let out = home
                    .command()
                    .arg(&shim)
                    .args(&args)
                    .env("PATH", &fake_path)
                    .env("FAKE_TYPE", kind)
                    .output()
                    .unwrap();
                assert_eq!(out.status.success(), kind == "empty");
                assert_eq!(
                    String::from_utf8_lossy(&out.stdout),
                    if kind == "empty" {
                        "native fallback"
                    } else {
                        ""
                    }
                );
            }
        }
        std::fs::remove_file(home.0.join("curl-argv")).unwrap();
        std::fs::write(home.0.join(".config/clipaste/token"), "invalid").unwrap();
        let out = home
            .command()
            .arg(&helper)
            .env("PATH", &fake_path)
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(
            !home.0.join("curl-argv").exists(),
            "invalid token reached curl"
        );
        assert!(!home
            .run(&build_remote_setup_script(URL, TOKEN).unwrap())
            .status
            .success());
        assert_eq!(
            std::fs::read_to_string(home.0.join(".config/clipaste/token")).unwrap(),
            "invalid"
        );
    }
    #[cfg(unix)]
    #[test]
    fn installer_refuses_rc_links_and_cleans_failure_staging() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let home = TempHome::new();
        let foreign = home.0.join("foreign");
        std::fs::write(&foreign, "keep").unwrap();
        symlink(&foreign, home.0.join(".zshrc")).unwrap();
        let script = build_remote_setup_script(URL, TOKEN).unwrap();
        assert!(!home.run(&script).status.success());
        assert!(!home.0.join(".local").exists());
        assert_eq!(std::fs::read_to_string(&foreign).unwrap(), "keep");
        std::fs::remove_file(home.0.join(".zshrc")).unwrap();
        let fake = home.0.join("fake-tools");
        std::fs::create_dir(&fake).unwrap();
        std::fs::write(fake.join("mv"), "#!/bin/bash\nexit 1\n").unwrap();
        std::fs::set_permissions(fake.join("mv"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut command = home.command();
        command.env("PATH", format!("{}:/usr/bin:/bin", fake.display()));
        let out = shell_output(command, &script);
        assert!(!out.status.success());
        assert_eq!(
            std::fs::read_dir(home.0.join(".local/bin"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            std::fs::read_dir(home.0.join(".config/clipaste"))
                .unwrap()
                .count(),
            0
        );
    }
    #[test]
    fn discovery_only_accepts_ips_and_auth_capable_metadata() {
        let candidates = wsl_host_candidates(
            Some("mirrored"),
            Some("127.0.0.1".into()),
            Some("evil;echo bad".into()),
        );
        assert_eq!(candidates.len(), 1);
        let nat = wsl_host_candidates(
            Some("nat"),
            Some("10.255.255.254".into()),
            Some("172.29.128.1".into()),
        );
        assert_eq!(
            nat.iter().map(|c| c.ip.as_str()).collect::<Vec<_>>(),
            ["10.255.255.254", "172.29.128.1", "127.0.0.1"]
        );
        assert_eq!(
            parse_resolv_nameserver("# hi\nnameserver\t172.29.128.1\n").as_deref(),
            Some("172.29.128.1")
        );
        assert_eq!(parse_resolv_nameserver("nameserver bad;code\n"), None);
        assert_eq!(
            parse_ip_route_default("default via 172.29.128.1 dev eth0\n").as_deref(),
            Some("172.29.128.1")
        );
        assert_eq!(
            parse_proc_net_route("Iface Destination Gateway\neth0 00000000 01801FAC\n").as_deref(),
            Some("172.31.128.1")
        );
        assert!(is_clipaste_health_body(
            "{ \"status\": \"ok\", \"auth\": \"bearer\" }"
        ));
        assert!(!is_clipaste_health_body("{\"status\":\"ok\"}"));
    }
}
