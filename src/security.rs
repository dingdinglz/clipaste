//! User-scoped credentials. Never put tokens in argv, logs, clipboard or cache.
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const TOKEN_LEN: usize = 64;

pub fn valid_token(token: &str) -> bool {
    token.len() == TOKEN_LEN
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn token_path() -> io::Result<PathBuf> {
    #[cfg(windows)]
    let root = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    let root = root.filter(|p| p.is_absolute()).ok_or_else(|| {
        io::Error::other(
            "a private absolute HOME/XDG_CONFIG_HOME (LOCALAPPDATA on Windows) is required",
        )
    })?;
    Ok(root.join("clipaste/token"))
}

fn private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(io::Error::other(
            "credential directory must be a real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::other(
                "credential directory is owned by another user",
            ));
        }
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Also used to import a Windows token explicitly into WSL. Refuse symlinks and
/// broad Unix permissions; the directory ACL supplies protection on Windows.
pub fn read_token(path: &Path) -> io::Result<String> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(io::Error::other(
            "token must be a regular, non-symlink file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let meta = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.uid() != unsafe { libc::geteuid() } || meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "token must be owned by you with permissions 0600",
            ));
        }
    }
    if !meta.is_file() || meta.len() > (TOKEN_LEN + 1) as u64 {
        return Err(io::Error::other("invalid token file"));
    }
    let mut token = String::new();
    Read::by_ref(&mut file)
        .take((TOKEN_LEN + 2) as u64)
        .read_to_string(&mut token)?;
    let token = token.strip_suffix('\n').unwrap_or(&token);
    if !valid_token(token) {
        return Err(io::Error::other(
            "token must contain exactly 64 lowercase hexadecimal characters",
        ));
    }
    Ok(token.to_string())
}

pub fn load_token() -> io::Result<String> {
    read_token(&token_path()?)
}

struct Staged(PathBuf);
impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn stage_token(path: &Path, token: &str) -> io::Result<Staged> {
    if !valid_token(token) {
        return Err(io::Error::other("invalid authentication token"));
    }
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("missing token directory"))?;
    private_dir(dir)?;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let staged = Staged(dir.join(format!(
            ".token-stage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&staged.0) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Do not remove a file that this invocation did not create.
                std::mem::forget(staged);
                continue;
            }
            Err(e) => {
                std::mem::forget(staged);
                return Err(e);
            }
        };
        file.write_all(token.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        return Ok(staged);
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    fs::File::open(path.parent().unwrap())?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn create_token_at(path: &Path) -> io::Result<String> {
    match read_token(path) {
        Ok(token) => return Ok(token),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
    let token = random
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let staged = stage_token(path, &token)?;
    // hard_link publishes the complete file without ever replacing a competing
    // creator's credential. NTFS and the Unix filesystems we support provide it.
    match fs::hard_link(&staged.0, path) {
        Ok(()) => {
            sync_parent(path)?;
            Ok(token)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => read_token(path),
        Err(e) => Err(e),
    }
}

pub fn load_or_create_token() -> io::Result<String> {
    create_token_at(&token_path()?)
}

// Exercise atomic credential replacement independently of the generated
// setup installer, which implements the same protocol on remote machines.
#[cfg(test)]
fn install_token_at(path: &Path, token: &str) -> io::Result<()> {
    match read_token(path) {
        Ok(existing) if existing == token => return Ok(()),
        Ok(_) => (),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    let staged = stage_token(path, token)?;
    fs::rename(&staged.0, path)?;
    sync_parent(path)
}

/// curl reads the secret from stdin, never command-line arguments. Ignore
/// curlrc/proxies so loopback clipboard traffic cannot be redirected elsewhere.
pub fn http_get_authenticated(url: &str, token: &str) -> Option<String> {
    if !valid_token(token) {
        return None;
    }
    let mut child = std::process::Command::new("curl")
        .args([
            "-q",
            "-sf",
            "--noproxy",
            "*",
            "--connect-timeout",
            "2",
            "--max-time",
            "5",
            "--max-filesize",
            "65536",
            "--config",
            "-",
            url,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let result = child
        .stdin
        .take()
        .and_then(|mut stdin| writeln!(stdin, "header = \"Authorization: Bearer {token}\"").ok());
    if result.is_none() {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    let output = child.wait_with_output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())
        .flatten()
}

/// Fixed-length credentials; do not short-circuit comparisons at the first byte.
pub fn tokens_equal(expected: &str, supplied: &str) -> bool {
    if supplied.len() != TOKEN_LEN || expected.len() != TOKEN_LEN {
        return false;
    }
    expected
        .bytes()
        .zip(supplied.bytes())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "clipaste-auth-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn generated_token_is_private_random_and_stable() {
        let dir = Dir::new();
        let path = dir.0.join("config/token");
        let token = create_token_at(&path).unwrap();
        assert!(valid_token(&token));
        assert_eq!(token, create_token_at(&path).unwrap());
        let other = create_token_at(&dir.0.join("other/token")).unwrap();
        assert_ne!(token, other);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }

    #[test]
    fn concurrent_creators_share_one_complete_token() {
        let dir = Dir::new();
        let path = dir.0.join("config/token");
        std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| create_token_at(&path).unwrap()))
                .collect();
            let expected = threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .collect::<Vec<_>>();
            assert!(expected.iter().all(|t| t == &expected[0]));
        });
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }

    #[test]
    fn invalid_credentials_are_not_overwritten() {
        let dir = Dir::new();
        let path = dir.0.join("config/token");
        private_dir(path.parent().unwrap()).unwrap();
        fs::write(&path, "not a token").unwrap();
        assert!(create_token_at(&path).is_err());
        assert!(install_token_at(&path, &"b".repeat(64)).is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "not a token");
    }

    #[test]
    fn installing_a_valid_token_is_atomic_and_idempotent() {
        let dir = Dir::new();
        let path = dir.0.join("config/token");
        install_token_at(&path, &"a".repeat(64)).unwrap();
        install_token_at(&path, &"b".repeat(64)).unwrap();
        install_token_at(&path, &"b".repeat(64)).unwrap();
        assert_eq!(read_token(&path).unwrap(), "b".repeat(64));
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_public_tokens_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = Dir::new();
        let target = dir.0.join("target");
        fs::write(&target, "a".repeat(64)).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_token(&target).is_err());
        let path = dir.0.join("token");
        symlink(&target, &path).unwrap();
        assert!(create_token_at(&path).is_err());
        assert!(install_token_at(&path, &"b".repeat(64)).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "a".repeat(64));
    }

    #[test]
    fn credential_comparison_requires_exact_token() {
        let token = "a".repeat(64);
        assert!(tokens_equal(&token, &token));
        assert!(!tokens_equal(&token, &"b".repeat(64)));
        assert!(!tokens_equal(&token, &format!("{token}x")));
        assert!(!valid_token(&"A".repeat(64)));
        assert!(!valid_token("$(id)"));
    }
}
