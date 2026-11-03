#[cfg(any(target_os = "macos", target_os = "windows", test))]
use image::codecs::png::PngEncoder;
#[cfg(any(target_os = "macos", target_os = "windows", test))]
use image::ImageEncoder;
use image::ImageFormat;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
#[cfg(any(target_os = "macos", test))]
use std::io::Read;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

pub const MAX_IMAGE_BYTES: usize = 64 * 1024 * 1024;
static CACHE_IO: Mutex<()> = Mutex::new(());

pub const VERSION: &str = "2.6.1-dingdinglz.1";
pub const DEFAULT_PORT: u16 = 18340;

pub fn supports_clipboard_host(os: &str) -> bool {
    matches!(os, "macos" | "windows" | "linux")
}

pub fn unsupported_host_message(os: &str) -> String {
    format!(
        "{os} clipboard host is not supported. The daemon requires macOS, Windows, or a Linux desktop.\n\
         Linux is supported as an SSH consumer: run `clipaste ssh-setup user@host` on \
         the clipboard host, then use `clipaste-paste` on the remote.\n\
         In WSL2, run `clipaste wsl-setup` with clipaste.exe running on Windows.\n\
         See https://github.com/dingdinglz/clipaste#install-from-source"
    )
}

/// Shared state: path to the most recently saved screenshot PNG
pub type LatestImage = Arc<Mutex<Option<PathBuf>>>;

pub fn temp_dir() -> PathBuf {
    // All writes validate configuration first: this fallback is diagnostic only.
    cache_root()
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("clipaste-unconfigured-{}", std::process::id()))
        })
        .join("clipaste")
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn cache_root() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        let p = PathBuf::from(xdg);
        if !p.as_os_str().is_empty() {
            return p.is_absolute().then_some(p);
        }
    }
    let home = PathBuf::from(std::env::var_os("HOME")?);
    home.is_absolute().then(|| home.join(".cache"))
}

#[cfg(target_os = "windows")]
fn cache_root() -> Option<PathBuf> {
    let local = PathBuf::from(std::env::var_os("LOCALAPPDATA")?);
    local.is_absolute().then_some(local)
}

pub fn ensure_temp_dir() -> io::Result<()> {
    let root = cache_root().ok_or_else(|| {
        io::Error::other(
            "PNG cache requires an absolute HOME/XDG_CACHE_HOME (LOCALAPPDATA on Windows)",
        )
    })?;
    ensure_cache_dir(&root.join("clipaste"))
}

fn ensure_cache_dir(dir: &Path) -> io::Result<()> {
    if let Ok(meta) = fs::symlink_metadata(dir) {
        if !meta.file_type().is_dir() {
            return Err(io::Error::other("PNG cache must be a real directory"));
        }
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    if !fs::symlink_metadata(dir)?.file_type().is_dir() {
        return Err(io::Error::other("PNG cache must be a real directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if fs::symlink_metadata(dir)?.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::other(
                "PNG cache is not owned by the current user",
            ));
        }
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Minimal HTTP GET via `curl`.
///
/// clipaste deliberately ships with no HTTP client crate — the only things it
/// ever fetches are its own endpoints on loopback or an SSH tunnel, and `curl`
/// is present on every platform we target (Windows 10+ bundles `curl.exe`).
/// Returns `None` on any transport error or non-2xx status (`-f`).
///
/// Timeouts are bounded: callers probe several candidate addresses in sequence,
/// and a firewall that DROPs instead of rejecting would otherwise stall each
/// attempt for minutes.
pub fn http_get(url: &str) -> Option<String> {
    let out = std::process::Command::new("curl")
        .args([
            "-q",
            "-sf",
            "--noproxy",
            "*",
            "--connect-timeout",
            "2",
            "-m",
            "5",
            "--max-filesize",
            "65536",
            url,
        ])
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

/// Escape a string for embedding in the hand-rolled JSON of `doctor --json`.
/// Kept here (rather than pulling in serde) because it is the only JSON we
/// ever *write* beyond fixed literals.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn log(msg: &str) {
    let now = chrono_lite();
    eprintln!("[{now}] clipaste: {msg}");
}

/// ISO8601-ish timestamp without pulling in chrono
fn chrono_lite() -> String {
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    // Good enough for logging — not calendar-accurate but unique and sortable
    format!("{secs}")
}

fn png_cache_name(bytes: &[u8]) -> String {
    format!("shot-sha256-{:x}.png", Sha256::digest(bytes))
}

/// Save PNG bytes at a stable, content-addressed path, reusing identical bytes.
///
/// Explicit recopies refresh retention for identical valid bytes. Cache expiry
/// runs while the daemon is alive and at its next startup.
/// A conflicting/corrupt cache entry is never replaced;
/// saving fails and logs an error so its owner can inspect or explicitly delete it.
pub fn save_png_to_temp(png_data: &[u8]) -> Option<PathBuf> {
    let result = ensure_temp_dir().and_then(|()| save_png_in_dir(&temp_dir(), png_data));
    match result {
        Ok(path) => Some(path),
        Err(e) => {
            log(&format!("failed to save cached PNG: {e}"));
            None
        }
    }
}

fn verify_cached_png(path: &Path, png_data: &[u8]) -> io::Result<()> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(io::Error::other("PNG cache entry must be a regular file"));
    }
    let file = open_regular_file(path, true)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    let mut reader = io::BufReader::new(file);
    // Streaming comparison bounds additional memory even for a corrupt entry.
    let mut remaining = png_data;
    loop {
        use std::io::BufRead;
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() && remaining.is_empty() {
            reader.get_ref().set_modified(SystemTime::now())?;
            return Ok(());
        }
        if chunk.is_empty() || !remaining.starts_with(chunk) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("PNG cache content mismatch at {}", path.display()),
            ));
        }
        let len = chunk.len();
        remaining = &remaining[len..];
        reader.consume(len);
    }
}

struct StagedPng(PathBuf);

impl Drop for StagedPng {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_file(&self.0) {
            // Windows publication moves the staging file to its final name.
            if e.kind() != io::ErrorKind::NotFound {
                log(&format!(
                    "failed to remove staging file {}: {e}",
                    self.0.display()
                ));
            }
        }
    }
}

#[cfg(unix)]
fn publish_no_replace(staged: &Path, path: &Path) -> io::Result<()> {
    fs::hard_link(staged, path)
}

#[cfg(target_os = "windows")]
fn publish_no_replace(staged: &Path, path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
    use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

    fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid PNG cache path");
        // Canonicalize the existing parent, not the possibly absent destination,
        // to retain Rust filesystem APIs' support for extended-length paths.
        let parent = path.parent().ok_or_else(invalid)?;
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let absolute = fs::canonicalize(parent)?.join(path.file_name().ok_or_else(invalid)?);
        let mut wide: Vec<u16> = absolute.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(invalid());
        }
        wide.push(0);
        Ok(wide)
    }

    let staged = wide_path(staged)?;
    let path = wide_path(path)?;
    // No REPLACE_EXISTING or COPY_ALLOWED: publish by same-volume rename without
    // clobbering a competing writer or requiring hard links on FAT/exFAT.
    // SAFETY: Both buffers are NUL-terminated and remain alive for the call.
    if unsafe { MoveFileExW(staged.as_ptr(), path.as_ptr(), 0) } != 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error().map(|code| code as u32) {
        Some(ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS) => {
            Err(io::Error::new(io::ErrorKind::AlreadyExists, error))
        }
        _ => Err(error),
    }
}

fn publish_staged_png(staged: &Path, path: &Path, png_data: &[u8]) -> io::Result<()> {
    match publish_no_replace(staged, path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => verify_cached_png(path, png_data),
        Err(e) => Err(e),
    }
}

fn save_png_in_dir(dir: &Path, png_data: &[u8]) -> io::Result<PathBuf> {
    if !validate_png(png_data) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid or oversized PNG",
        ));
    }
    let _io = CACHE_IO.lock().unwrap();
    ensure_cache_dir(dir)?;
    let path = dir.join(png_cache_name(png_data));
    match verify_cached_png(&path, png_data) {
        Ok(()) => return Ok(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    static NEXT: AtomicU64 = AtomicU64::new(0);
    let (staged, mut file) = loop {
        let scratch = dir.join(format!(
            ".png-stage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&scratch) {
            Ok(file) => break (StagedPng(scratch), file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(png_data)?;
    file.sync_all()?;
    drop(file);
    // Publish only the complete, flushed, closed file, without replacing an entry.
    publish_staged_png(&staged.0, &path, png_data)?;
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    Ok(path)
}

fn parse_cache_ttl(value: Option<&str>) -> Result<Option<Duration>, String> {
    let value = value.unwrap_or("3600");
    if value.is_empty() || !value.bytes().all(|c| c.is_ascii_digit()) {
        return Err(
            "CLIPASTE_CACHE_TTL_SECONDS must be a nonnegative integer (0 disables expiry)".into(),
        );
    }
    let seconds = value
        .parse::<u64>()
        .map_err(|_| "CLIPASTE_CACHE_TTL_SECONDS is too large".to_string())?;
    Ok((seconds != 0).then(|| Duration::from_secs(seconds)))
}

pub fn cache_ttl() -> Result<Option<Duration>, String> {
    match std::env::var("CLIPASTE_CACHE_TTL_SECONDS") {
        Ok(value) => parse_cache_ttl(Some(&value)),
        Err(std::env::VarError::NotPresent) => parse_cache_ttl(None),
        Err(_) => Err("CLIPASTE_CACHE_TTL_SECONDS must be valid UTF-8".into()),
    }
}

fn image_is_fresh_at(path: &Path, ttl: Option<Duration>, now: SystemTime) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.file_type().is_file() || meta.len() > MAX_IMAGE_BYTES as u64 {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.uid() != unsafe { libc::geteuid() } || meta.permissions().mode() & 0o077 != 0 {
            return false;
        }
    }
    let Some(ttl) = ttl else {
        return true;
    };
    meta.modified()
        .is_ok_and(|modified| now.duration_since(modified).unwrap_or_default() < ttl)
}

pub fn cached_image_is_fresh(path: &Path) -> bool {
    cache_ttl().is_ok_and(|ttl| image_is_fresh_at(path, ttl, SystemTime::now()))
}

fn managed_cache_name(name: &str) -> bool {
    fn digits(value: &str) -> bool {
        !value.is_empty() && value.bytes().all(|c| c.is_ascii_digit())
    }
    if let Some(hash) = name
        .strip_prefix("shot-sha256-")
        .and_then(|s| s.strip_suffix(".png"))
    {
        return hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit());
    }
    if let Some(stamp) = name
        .strip_prefix("shot-")
        .and_then(|s| s.strip_suffix(".png"))
    {
        // Legacy v2.3 base36 milliseconds and numeric timestamp forms. Limit
        // base36 to plausible timestamps, not arbitrary shot-*.png names.
        return (stamp.split('-').all(digits) && stamp.split('-').count() <= 2)
            || (stamp
                .bytes()
                .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase())
                && u64::from_str_radix(stamp, 36)
                    .is_ok_and(|ms| (1_500_000_000_000..=4_102_444_800_000).contains(&ms)));
    }
    if let Some(stamp) = name
        .strip_prefix("screenshot-")
        .and_then(|s| s.strip_suffix(".png"))
    {
        return digits(stamp);
    }
    if let Some(stage) = name.strip_prefix(".png-stage-") {
        return stage.split('-').count() == 2 && stage.split('-').all(digits);
    }
    false
}

fn cleanup_cache_at(
    dir: &Path,
    latest: &LatestImage,
    ttl: Option<Duration>,
    now: SystemTime,
) -> io::Result<()> {
    let _io = CACHE_IO.lock().unwrap();
    ensure_cache_dir(dir)?;
    let mut staged = latest.lock().unwrap();
    if staged
        .as_ref()
        .is_some_and(|p| !image_is_fresh_at(p, ttl, now))
    {
        *staged = None;
    }
    let Some(ttl) = ttl else {
        return Ok(());
    };
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_name().to_str().is_some_and(managed_cache_name) {
            continue;
        }
        let path = entry.path();
        // symlink_metadata, never metadata: don't delete or follow a symlink.
        if fs::symlink_metadata(&path)?.file_type().is_file()
            && fs::symlink_metadata(&path)?
                .modified()
                .is_ok_and(|modified| now.duration_since(modified).unwrap_or_default() >= ttl)
        {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

/// Validate before the server starts. Expiry requires a running daemon; the
/// startup pass also removes leftovers from times when it was stopped.
pub fn start_cache_cleanup(latest: LatestImage) -> Result<(), String> {
    let ttl = cache_ttl()?;
    ensure_temp_dir().map_err(|e| format!("Cannot initialize PNG cache: {e}"))?;
    let dir = temp_dir();
    cleanup_cache_at(&dir, &latest, ttl, SystemTime::now()).map_err(|e| e.to_string())?;
    std::thread::Builder::new()
        .name("cache-cleanup".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(60));
            if let Err(e) = cleanup_cache_at(&dir, &latest, ttl, SystemTime::now()) {
                log(&format!("PNG cache cleanup failed: {e}"));
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn open_regular_file(path: &Path, writable: bool) -> io::Result<fs::File> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(io::Error::other(
            "Image must be a regular file, not a symlink",
        ));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true).write(writable);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("Image must be a regular file"));
    }
    Ok(file)
}

fn decode_bounded(bytes: &[u8], format: ImageFormat) -> Option<image::DynamicImage> {
    if bytes.len() > MAX_IMAGE_BYTES {
        return None;
    }
    let mut reader = image::ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(16384);
    limits.max_image_height = Some(16384);
    limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(limits);
    let img = reader.decode().ok()?;
    // Conversion to RGBA must also fit the allocation budget, independently of
    // the source decoder's pixel layout.
    if u64::from(img.width()) * u64::from(img.height()) * 4 > 128 * 1024 * 1024 {
        return None;
    }
    Some(img)
}

pub fn validate_png(bytes: &[u8]) -> bool {
    decode_bounded(bytes, ImageFormat::Png).is_some()
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn encode_png(img: image::DynamicImage) -> Option<Vec<u8>> {
    let rgba = img.to_rgba8();
    // Bound even encoder output, not just the resulting allocation afterward.
    struct Bounded(Vec<u8>);
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > MAX_IMAGE_BYTES.saturating_sub(self.0.len()) {
                return Err(io::Error::other("PNG output exceeds 64 MiB"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut buf = Bounded(Vec::new());
    PngEncoder::new(&mut buf)
        .write_image(
            rgba.as_raw(),
            rgba.width(),
            rgba.height(),
            image::ExtendedColorType::Rgba8,
        )
        .ok()?;
    Some(buf.0)
}

#[cfg(target_os = "macos")]
pub fn tiff_to_png(tiff_data: &[u8]) -> Option<Vec<u8>> {
    encode_png(decode_bounded(tiff_data, ImageFormat::Tiff)?)
}

/// Extension selects a decoder, never a trust decision. Reject links and bound
/// both the source read and the decoder before publishing any clipboard file.
#[cfg(any(target_os = "macos", test))]
pub fn image_file_to_png(path: &Path) -> Option<Vec<u8>> {
    let format = match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "png" => ImageFormat::Png,
        "tif" | "tiff" => ImageFormat::Tiff,
        "bmp" => ImageFormat::Bmp,
        _ => return None,
    };
    let file = open_regular_file(path, false).ok()?;
    if file.metadata().ok()?.len() > MAX_IMAGE_BYTES as u64 {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_IMAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    let image = decode_bounded(&bytes, format)?;
    if format == ImageFormat::Png {
        Some(bytes)
    } else {
        encode_png(image)
    }
}

/// Convert Windows DIB (CF_DIB) bytes to PNG bytes
#[cfg(target_os = "windows")]
pub fn dib_to_png(dib_data: &[u8]) -> Option<Vec<u8>> {
    // CF_DIB is a BITMAPINFOHEADER followed by pixel data
    // The image crate's BMP decoder expects a full BMP file header,
    // so we prepend a minimal BITMAPFILEHEADER
    if dib_data.len() < 40 || dib_data.len() > MAX_IMAGE_BYTES {
        return None;
    }

    // Read BITMAPINFOHEADER fields
    let header_size = u32::from_le_bytes(dib_data[0..4].try_into().ok()?) as usize;
    let bits_per_pixel = u16::from_le_bytes(dib_data[14..16].try_into().ok()?);
    let compression = u32::from_le_bytes(dib_data[16..20].try_into().ok()?);

    // Calculate color table size
    let color_table_size = if bits_per_pixel <= 8 {
        (1 << bits_per_pixel) * 4
    } else if compression == 3 {
        // BI_BITFIELDS: 3 DWORD masks
        12
    } else {
        0
    };

    let pixel_offset = 14 + header_size + color_table_size; // 14 = BITMAPFILEHEADER
    let file_size = 14 + dib_data.len();

    // Build BMP file header (14 bytes)
    let mut bmp = Vec::with_capacity(file_size);
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&(file_size as u32).to_le_bytes());
    bmp.extend_from_slice(&0u16.to_le_bytes()); // reserved1
    bmp.extend_from_slice(&0u16.to_le_bytes()); // reserved2
    bmp.extend_from_slice(&(pixel_offset as u32).to_le_bytes());
    bmp.extend_from_slice(dib_data);

    encode_png(decode_bounded(&bmp, ImageFormat::Bmp)?)
}

pub fn print_help() {
    println!(
        "clipaste v{VERSION} — Fix screenshot paste in terminals (local + SSH + WSL2)

USAGE
  clipaste                       Run daemon (macOS, Windows, Linux desktop)
  clipaste doctor [--json]       Diagnose this machine and print the fix command
  clipaste ssh-setup user@host   Configure remote server for image paste via SSH
                                 (add -p PORT for a custom SSH port)
  clipaste wsl-setup             Configure WSL2 for image paste from Windows host
                                 (--host IP; first setup: --token-file PATH)
  clipaste --version             Print version
  clipaste --help                Show this help

FOR CODING AGENTS
  `clipaste doctor --json` is the machine-readable entry point. Every check
  carries name/status/detail/fix; `fix` is a literal command to run.
  Exit 0 = usable, 1 = broken, 2 = bad arguments. All setup commands are
  non-interactive. See AGENTS.md in the repo for the full install recipe.

  On the remote, ssh-setup/wsl-setup also install a `clipaste-paste` command:
  it fetches the current clipboard image into a real file and prints its path.
  Use it with Codex CLI (which bypasses the xclip shim) or any macOS remote.

WHAT IT DOES
  Local:  Watches the clipboard and caches qualifying images privately.
          The clipboard is left unchanged by default. Explicitly set
          CLIPASTE_SERVER_ONLY=0 for local file-path normalization.
          Images expire after one hour; cleanup runs at startup and every
          minute while running. CLIPASTE_CACHE_TTL_SECONDS=0 opts into
          indefinite retention. Deletion is not secure erasure.
          Linux reads image/png without modifying the clipboard.

  SSH:    Runs a loopback HTTP server on port {DEFAULT_PORT}. Clipboard
          endpoints require a private bearer token. Use 'ssh-setup' to
          configure a trusted SSH remote and transfer credentials securely.
          Claude Code (Linux remote) pastes natively with Ctrl+V; Codex CLI
          and macOS remotes use the `clipaste-paste` helper.

  WSL2:   Run 'wsl-setup' inside WSL2 to install xclip shim that fetches
          images from clipaste.exe on the Windows host. No SSH needed.
          Import a private Windows token using --token-file PATH on first
          setup. --host accepts a literal IP only. Prefer mirrored networking;
          NAT cannot directly reach the Windows loopback listener.

COMPATIBILITY
  Host:    macOS, Windows, Linux desktop (Wayland data-control or X11/XWayland)
  macOS:   Ghostty, Alacritty, iTerm2, Terminal.app, WezTerm, Kitty
  Windows: Windows Terminal, PowerShell, cmd.exe
  Remote:  Linux and macOS via SSH from a supported clipboard host
  WSL2:    Consumer only; requires clipaste.exe running on Windows

  Linux:   Install wl-clipboard 2.2+ for native Wayland, or xclip
           for X11/XWayland, plus curl. Run inside your graphical session.
           Auto mode warns before using XWayland if data-control is unavailable.
           CLIPASTE_BACKEND=wayland or x11 selects a backend explicitly.
           No local text-path injection; SSH consumers use the existing helpers.

MORE INFO
  https://github.com/dingdinglz/clipaste"
    );
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            loop {
                let path = std::env::temp_dir().join(format!(
                    "clipaste-common-test-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("{e}"),
                }
            }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn png(value: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        PngEncoder::new(&mut bytes)
            .write_image(&[value, 0, 0, 255], 1, 1, image::ExtendedColorType::Rgba8)
            .unwrap();
        bytes
    }

    #[test]
    fn creates_missing_cache_directory() {
        let dir = TestDir::new();
        let bytes = png(1);
        let path = save_png_in_dir(&dir.0.join("cache"), &bytes).unwrap();
        assert_eq!(fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn publication_preserves_complete_file_after_staging_cleanup() {
        let dir = TestDir::new();
        let staged = StagedPng(dir.0.join(".png-stage-test"));
        let path = dir.0.join("published.png");
        let bytes = png(1);
        fs::write(&staged.0, &bytes).unwrap();
        publish_staged_png(&staged.0, &path, &bytes).unwrap();
        #[cfg(target_os = "windows")]
        assert!(!staged.0.exists());
        #[cfg(unix)]
        assert!(staged.0.exists());
        drop(staged);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    #[test]
    fn publication_verifies_competing_writer_without_replacing_it() {
        let dir = TestDir::new();
        let path = dir.0.join("published.png");
        let bytes = png(1);
        for existing in [&bytes, &png(2)] {
            fs::write(&path, existing).unwrap();
            let staged = StagedPng(dir.0.join(".png-stage-test"));
            fs::write(&staged.0, &bytes).unwrap();
            let result = publish_staged_png(&staged.0, &path, &bytes);
            if existing == &bytes {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            }
            assert_eq!(fs::read(&path).unwrap(), *existing);
            assert_eq!(fs::read(&staged.0).unwrap(), bytes);
            drop(staged);
            assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
        }
    }

    #[test]
    fn publication_failure_does_not_leave_staging_files() {
        let dir = TestDir::new();
        let staged = StagedPng(dir.0.join(".png-stage-test"));
        let path = dir.0.join("missing").join("published.png");
        let bytes = png(1);
        fs::write(&staged.0, &bytes).unwrap();
        assert!(publish_staged_png(&staged.0, &path, &bytes).is_err());
        drop(staged);
        assert!(!path.exists());
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
    }

    #[test]
    fn rapid_distinct_images_never_overwrite_each_other() {
        let dir = TestDir::new();
        let saved: Vec<_> = (0..32)
            .map(|value| {
                let bytes = png(value);
                (save_png_in_dir(&dir.0, &bytes).unwrap(), bytes)
            })
            .collect();
        for (path, bytes) in saved {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn identical_bytes_reuse_published_file_across_processes() {
        let dir = TestDir::new();
        let bytes = png(9);
        let path = save_png_in_dir(&dir.0, &bytes).unwrap();
        let old = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1);
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(old))
            .unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "common::cache_tests::cache_process_child"])
            .env("CLIPASTE_TEST_CACHE_DIR", &dir.0)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
        assert!(fs::metadata(&path).unwrap().modified().unwrap() > old);
        assert_eq!(fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn cache_process_child() {
        if let Some(dir) = std::env::var_os("CLIPASTE_TEST_CACHE_DIR") {
            save_png_in_dir(Path::new(&dir), &png(9)).unwrap();
        }
    }

    #[test]
    fn cache_names_have_a_fixed_algorithm() {
        assert_eq!(
            png_cache_name(b""),
            "shot-sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.png"
        );
        assert_eq!(
            png_cache_name(b"a"),
            "shot-sha256-ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb.png"
        );
    }

    #[test]
    fn conflicting_or_corrupt_file_is_not_overwritten() {
        let dir = TestDir::new();
        let bytes = png(1);
        let path = dir.0.join(png_cache_name(&bytes));
        for corrupt in [b"truncated".as_slice(), png(2).as_slice()] {
            fs::write(&path, corrupt).unwrap();
            let error = save_png_in_dir(&dir.0, &bytes).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(fs::read(&path).unwrap(), corrupt);
            assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
        }
    }

    #[test]
    fn concurrent_writers_publish_complete_deduplicated_files() {
        let dir = TestDir::new();
        let barrier = std::sync::Barrier::new(16);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|n| {
                    let barrier = &barrier;
                    let dir = &dir.0;
                    scope.spawn(move || {
                        let bytes = png(n % 4);
                        barrier.wait();
                        let path = save_png_in_dir(dir, &bytes).unwrap();
                        assert_eq!(fs::read(&path).unwrap(), bytes);
                        (n % 4, path)
                    })
                })
                .collect();
            for handle in handles {
                let (value, path) = handle.join().unwrap();
                assert_eq!(path, dir.0.join(png_cache_name(&png(value))));
            }
        });
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 4);
    }

    fn set_mtime(path: &Path, time: SystemTime) {
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(time)
            .unwrap();
    }

    #[test]
    fn ttl_parser_defaults_and_explicit_opt_out_are_strict() {
        assert_eq!(
            parse_cache_ttl(None).unwrap(),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(parse_cache_ttl(Some("0")).unwrap(), None);
        assert_eq!(
            parse_cache_ttl(Some("120")).unwrap(),
            Some(Duration::from_secs(120))
        );
        for invalid in [
            "",
            "-1",
            "+1",
            " 1",
            "1 ",
            "1.0",
            "forever",
            "18446744073709551616",
        ] {
            assert!(parse_cache_ttl(Some(invalid)).is_err(), "{invalid}");
        }
    }

    #[test]
    fn cleanup_expires_only_managed_regular_files_and_clears_staged_path() {
        let dir = TestDir::new();
        let ttl = Some(Duration::from_secs(3600));
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10000);
        let current = save_png_in_dir(&dir.0, &png(1)).unwrap();
        set_mtime(&current, now - Duration::from_secs(3599));
        let expired = save_png_in_dir(&dir.0, &png(2)).unwrap();
        set_mtime(&expired, now - Duration::from_secs(3600));
        let latest = LatestImage::new(Mutex::new(Some(current.clone())));
        let legacy_names = [
            "shot-1700000000000.png",
            "shot-1700000000-123.png",
            "shot-loyw3v28.png",
            "screenshot-1700000000000.png",
            ".png-stage-123-4",
        ];
        for name in legacy_names {
            let path = dir.0.join(name);
            fs::write(&path, b"legacy").unwrap();
            set_mtime(&path, SystemTime::UNIX_EPOCH);
        }
        let unrelated = dir.0.join("shot-old-timestamp.png");
        fs::write(&unrelated, b"not ours").unwrap();
        set_mtime(&unrelated, SystemTime::UNIX_EPOCH);
        let token = dir.0.join("token");
        fs::write(&token, b"not ours either").unwrap();
        set_mtime(&token, SystemTime::UNIX_EPOCH);
        let directory = dir.0.join("shot-123.png");
        fs::create_dir(&directory).unwrap();
        cleanup_cache_at(&dir.0, &latest, ttl, now).unwrap();
        assert_eq!(*latest.lock().unwrap(), Some(current.clone()));
        assert!(current.exists());
        assert!(!expired.exists());
        for name in legacy_names {
            assert!(!dir.0.join(name).exists(), "{name}");
        }
        assert!(unrelated.exists());
        assert!(token.exists());
        assert!(directory.is_dir());
        cleanup_cache_at(&dir.0, &latest, ttl, now + Duration::from_secs(1)).unwrap();
        assert!(latest.lock().unwrap().is_none());
        assert!(!current.exists());
    }

    #[test]
    fn ttl_zero_keeps_old_files_and_explicit_recopy_refreshes_timestamp() {
        let dir = TestDir::new();
        let bytes = png(1);
        let path = save_png_in_dir(&dir.0, &bytes).unwrap();
        set_mtime(&path, SystemTime::UNIX_EPOCH);
        let latest = LatestImage::new(Mutex::new(Some(path.clone())));
        cleanup_cache_at(&dir.0, &latest, None, SystemTime::now()).unwrap();
        assert!(path.exists());
        assert_eq!(*latest.lock().unwrap(), Some(path.clone()));
        assert_eq!(save_png_in_dir(&dir.0, &bytes).unwrap(), path);
        assert!(fs::metadata(&path).unwrap().modified().unwrap() > SystemTime::UNIX_EPOCH);
        assert!(image_is_fresh_at(
            &path,
            Some(Duration::from_secs(3600)),
            SystemTime::now()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_and_freshness_never_follow_symlinks_or_publish_public_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = TestDir::new();
        let outside = TestDir::new();
        let target = outside.0.join("target");
        fs::write(&target, png(3)).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        set_mtime(&target, SystemTime::UNIX_EPOCH);
        let link = dir.0.join("shot-123.png");
        symlink(&target, &link).unwrap();
        let latest = LatestImage::new(Mutex::new(Some(link.clone())));
        assert!(!image_is_fresh_at(&link, None, SystemTime::now()));
        cleanup_cache_at(
            &dir.0,
            &latest,
            Some(Duration::from_secs(1)),
            SystemTime::now(),
        )
        .unwrap();
        assert!(latest.lock().unwrap().is_none());
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
        assert!(target.exists());
        assert!(!image_is_fresh_at(&target, None, SystemTime::now()));
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(image_is_fresh_at(&target, None, SystemTime::now()));
    }

    #[test]
    fn image_input_requires_valid_png_and_bounded_source_and_dimensions() {
        let dir = TestDir::new();
        let path = dir.0.join("input.png");
        fs::write(&path, b"not actually PNG").unwrap();
        assert!(image_file_to_png(&path).is_none());
        assert!(save_png_in_dir(&dir.0, b"not PNG").is_err());
        let bytes = png(1);
        fs::write(&path, &bytes).unwrap();
        assert_eq!(image_file_to_png(&path), Some(bytes.clone()));
        fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
        assert!(image_file_to_png(&path).is_none());
        fs::File::create(&path)
            .unwrap()
            .set_len(MAX_IMAGE_BYTES as u64 + 1)
            .unwrap();
        assert!(image_file_to_png(&path).is_none());
        let mut oversized_dimensions = Vec::new();
        PngEncoder::new(&mut oversized_dimensions)
            .write_image(
                &vec![0; 16385 * 4],
                16385,
                1,
                image::ExtendedColorType::Rgba8,
            )
            .unwrap();
        assert!(!validate_png(&oversized_dimensions));
    }

    #[cfg(unix)]
    #[test]
    fn copied_png_symlink_is_rejected() {
        let dir = TestDir::new();
        let original = dir.0.join("original.png");
        let link = dir.0.join("link.png");
        fs::write(&original, png(1)).unwrap();
        std::os::unix::fs::symlink(&original, &link).unwrap();
        assert!(image_file_to_png(&link).is_none());
        assert!(image_file_to_png(&original).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_cache_entries_and_directories_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = TestDir::new();
        let cache = dir.0.join("cache");
        fs::create_dir(&cache).unwrap();
        let bytes = png(1);
        let outside = dir.0.join("outside.png");
        fs::write(&outside, &bytes).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o644)).unwrap();
        let path = cache.join(png_cache_name(&bytes));
        symlink(&outside, &path).unwrap();
        assert!(save_png_in_dir(&cache, &bytes).is_err());
        assert_eq!(fs::read(&outside).unwrap(), bytes);
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let linked_dir = dir.0.join("linked-cache");
        symlink(&cache, &linked_dir).unwrap();
        assert!(save_png_in_dir(&linked_dir, &bytes).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cache_directory_and_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new();
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        let path = save_png_in_dir(&dir.0, &png(1)).unwrap();
        assert_eq!(
            fs::metadata(&dir.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(save_png_in_dir(&dir.0, &png(1)).unwrap(), path);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
