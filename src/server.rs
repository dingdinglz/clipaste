use crate::common::{self, LatestImage};
use crate::security;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_HEADERS: usize = 8192;
const MAX_CONNECTIONS: usize = 16;
const HEADER_TIMEOUT: Duration = Duration::from_secs(3);
// Authenticated payloads can cross a slow SSH link. This is an overall
// deadline, not a per-write timer that could be extended indefinitely.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(180);

/// The listener never leaves loopback. A token is required even through SSH:
/// loopback TCP is shared by all accounts on the remote machine.
pub fn start(latest: LatestImage, server_only: bool, token: String) -> io::Result<()> {
    if !security::valid_token(&token) {
        return Err(io::Error::other("invalid server credential"));
    }
    let addr = format!("127.0.0.1:{}", common::DEFAULT_PORT);
    let listener = TcpListener::bind(&addr)?;
    common::log(&format!("authenticated http server listening on {addr}"));
    let token = Arc::new(token);
    let connections = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            if connections.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
                connections.fetch_sub(1, Ordering::Relaxed);
                // Do not block the accept loop writing to a client that may
                // never read. Dropping it is deliberate overload backpressure.
                continue;
            }
            let slot = ConnectionSlot(connections.clone());
            let latest = latest.clone();
            let token = token.clone();
            let _ = std::thread::Builder::new()
                .name("clipaste-http".into())
                .spawn(move || {
                    let _slot = slot;
                    handle_request(stream, latest, server_only, &token);
                });
        }
    });
    Ok(())
}

struct ConnectionSlot(Arc<AtomicUsize>);
impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Health is public metadata only, so setup can discover a WSL host before
/// importing its token. Clipboard availability and image bytes are private.
pub(crate) fn health_body(server_only: bool) -> String {
    let mode = if server_only {
        ",\"mode\":\"server-only\""
    } else {
        ""
    };
    format!(
        "{{\"status\":\"ok\",\"version\":\"{}\",\"auth\":\"bearer\"{mode}}}",
        common::VERSION
    )
}

struct Request<'a> {
    path: &'a str,
    bearer: Option<&'a str>,
}

fn valid_host(host: &str) -> bool {
    let (name, port) = host.rsplit_once(':').unwrap_or((host, "80"));
    // WSL may address the Windows host through a literal private IP. Domain
    // names other than localhost are never accepted (DNS rebinding).
    let literal = name
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(name);
    (name == "localhost" || literal.parse::<std::net::IpAddr>().is_ok())
        && port.parse::<u16>().is_ok_and(|p| p > 0)
}

fn parse_request(bytes: &[u8]) -> Result<Request<'_>, u16> {
    let text = std::str::from_utf8(bytes).map_err(|_| 400u16)?;
    if !text.ends_with("\r\n\r\n") || bytes.len() > MAX_HEADERS {
        return Err(400);
    }
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or("").split_whitespace();
    if first.next() != Some("GET") {
        return Err(405);
    }
    let path = first.next().ok_or(400u16)?;
    if !matches!(first.next(), Some("HTTP/1.0" | "HTTP/1.1")) || first.next().is_some() {
        return Err(400);
    }
    let mut host = None;
    let mut bearer = None;
    let mut seen_auth = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(400u16)?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value).is_some() || !valid_host(value) {
                return Err(403);
            }
        } else if name.eq_ignore_ascii_case("origin") {
            // No browser client is part of the protocol. This plus Host
            // validation blocks DNS-rebinding/cross-origin clipboard access.
            return Err(403);
        } else if name.eq_ignore_ascii_case("authorization") {
            if seen_auth {
                return Err(400);
            }
            seen_auth = true;
            bearer = value.strip_prefix("Bearer ");
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value != "0")
        {
            return Err(400);
        }
    }
    if host.is_none() {
        return Err(400);
    }
    Ok(Request { path, bearer })
}

struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}
impl Response {
    fn new(status: u16, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type,
            body: body.into(),
        }
    }
    fn error(status: u16) -> Self {
        Self::new(status, "text/plain", b"request refused\n".to_vec())
    }
}

fn fresh_path(latest: &LatestImage) -> Option<std::path::PathBuf> {
    let path = latest.lock().ok()?.clone()?;
    if common::cached_image_is_fresh(&path) {
        return Some(path);
    }
    if let Ok(mut guard) = latest.lock() {
        if guard.as_ref() == Some(&path) {
            // An identical-byte recopy can refresh this same cache path between
            // the first metadata check and acquiring the state lock.
            if common::cached_image_is_fresh(&path) {
                return Some(path);
            }
            *guard = None;
        }
    }
    None
}

fn route(request: Request<'_>, latest: &LatestImage, server_only: bool, token: &str) -> Response {
    if request.path == "/health" {
        return Response::new(
            200,
            "application/json",
            health_body(server_only).into_bytes(),
        );
    }
    if !request
        .bearer
        .is_some_and(|s| security::tokens_equal(token, s))
    {
        return Response::error(401);
    }
    match request.path {
        "/clipboard/type" => {
            let kind = fresh_path(latest)
                .as_deref()
                .and_then(common::clipboard_kind);
            let body = match kind {
                Some(common::ClipboardKind::Image) => {
                    b"{\"type\":\"image\",\"format\":\"png\"}".as_slice()
                }
                Some(common::ClipboardKind::Markdown) => {
                    b"{\"type\":\"file\",\"format\":\"md\"}".as_slice()
                }
                None => b"{\"type\":\"empty\"}".as_slice(),
            };
            Response::new(200, "application/json", body.to_vec())
        }
        "/clipboard/image" | "/clipboard/file" => {
            let Some(path) = fresh_path(latest) else {
                return Response::new(204, "text/plain", Vec::new());
            };
            let expected = if request.path == "/clipboard/image" {
                common::ClipboardKind::Image
            } else {
                common::ClipboardKind::Markdown
            };
            if common::clipboard_kind(&path) != Some(expected) {
                return Response::new(204, "text/plain", Vec::new());
            }
            let limit = match expected {
                common::ClipboardKind::Image => common::MAX_IMAGE_BYTES as u64,
                common::ClipboardKind::Markdown => common::MAX_MARKDOWN_BYTES as u64,
            };
            let read = || -> io::Result<Vec<u8>> {
                let mut options = std::fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NOFOLLOW);
                }
                let file = options.open(&path)?;
                let meta = file.metadata()?;
                if !meta.is_file() || meta.len() > limit {
                    return Err(io::Error::other("invalid cached clipboard file"));
                }
                let mut data = Vec::new();
                file.take(limit + 1).read_to_end(&mut data)?;
                if data.len() as u64 > limit {
                    return Err(io::Error::other("clipboard file too large"));
                }
                if expected == common::ClipboardKind::Markdown && !common::validate_markdown(&data)
                {
                    return Err(io::Error::other("invalid cached Markdown"));
                }
                Ok(data)
            };
            match read() {
                Ok(data) => Response::new(
                    200,
                    if expected == common::ClipboardKind::Image {
                        "image/png"
                    } else {
                        "text/markdown; charset=utf-8"
                    },
                    data,
                ),
                Err(_) => Response::error(404),
            }
        }
        _ => Response::error(404),
    }
}

fn read_headers(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let deadline = Instant::now() + HEADER_TIMEOUT;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "header deadline"))?;
        stream.set_read_timeout(Some(remaining))?;
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::other("incomplete request"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HEADERS {
            return Err(io::Error::other("headers too large"));
        }
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            buf.truncate(end + 4);
            return Ok(buf);
        }
    }
}

fn response_timeout(response: &Response) -> Duration {
    if response.status == 200
        && matches!(
            response.content_type,
            "image/png" | "text/markdown; charset=utf-8"
        )
    {
        TRANSFER_TIMEOUT
    } else {
        HEADER_TIMEOUT
    }
}

fn write_until<W: Write>(
    writer: &mut W,
    mut bytes: &[u8],
    deadline: Instant,
    mut set_timeout: impl FnMut(&mut W, Duration) -> io::Result<()>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "response deadline"))?;
        set_timeout(writer, remaining)?;
        match writer.write(&bytes[..bytes.len().min(64 * 1024)]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "response write stalled",
                ))
            }
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn handle_request(mut stream: TcpStream, latest: LatestImage, server_only: bool, token: &str) {
    if stream.set_read_timeout(Some(HEADER_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(HEADER_TIMEOUT)).is_err()
    {
        return;
    }
    let response = match read_headers(&mut stream) {
        Ok(bytes) => match parse_request(&bytes) {
            Ok(request) => route(request, &latest, server_only, token),
            Err(status) => Response::error(status),
        },
        Err(_) => Response::error(400),
    };
    let status_text = match response.status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let auth = if response.status == 401 {
        "WWW-Authenticate: Bearer\r\n"
    } else {
        ""
    };
    let header = format!(
        "HTTP/1.1 {} {status_text}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n{auth}Connection: close\r\n\r\n",
        response.status, response.content_type, response.body.len()
    );
    let deadline = Instant::now() + response_timeout(&response);
    let timeout = |socket: &mut TcpStream, remaining| socket.set_write_timeout(Some(remaining));
    if write_until(&mut stream, header.as_bytes(), deadline, timeout).is_ok() {
        let _ = write_until(&mut stream, &response.body, deadline, timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(path: &str, header: &str) -> Response {
        let text = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:18340\r\n{header}\r\n");
        let latest = LatestImage::default();
        match parse_request(text.as_bytes()) {
            Ok(req) => route(req, &latest, true, &"a".repeat(64)),
            Err(status) => Response::error(status),
        }
    }
    #[test]
    fn metadata_is_public_but_clipboard_needs_authentication() {
        let health = response("/health", "");
        assert_eq!(health.status, 200);
        assert!(String::from_utf8(health.body)
            .unwrap()
            .contains("\"auth\":\"bearer\""));
        for path in ["/clipboard/type", "/clipboard/image", "/clipboard/file"] {
            assert_eq!(response(path, "").status, 401);
            assert_eq!(
                response(
                    path,
                    &format!("Authorization: Bearer {}\r\n", "b".repeat(64))
                )
                .status,
                401
            );
        }
        let header = format!("Authorization: Bearer {}\r\n", "a".repeat(64));
        assert_eq!(response("/clipboard/type", &header).status, 200);
        assert_eq!(response("/clipboard/image", &header).status, 204);
        assert_eq!(response("/clipboard/file", &header).status, 204);
        assert_eq!(response("/clipboard/image-extra", &header).status, 404);
    }
    #[test]
    fn browser_origins_host_spoofing_and_duplicate_credentials_are_refused() {
        for raw in [
            "GET /health HTTP/1.1\r\nHost: attacker.example:18340\r\n\r\n",
            "GET /health HTTP/1.1\r\nHost: localhost\r\nOrigin: https://attacker.example\r\n\r\n",
            "GET /health HTTP/1.1\r\nHost: localhost\r\nHost: localhost\r\n\r\n",
            "GET /health HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer x\r\nAuthorization: Bearer y\r\n\r\n",
        ] { assert!(parse_request(raw.as_bytes()).is_err()); }
    }
    #[test]
    fn malformed_and_oversized_requests_are_refused() {
        for raw in [
            "GET /health HTTP/1.1\r\n\r\n",
            "GET /health HTTP/1.1 extra\r\nHost: localhost\r\n\r\n",
            "POST /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "GET /health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\n",
        ] {
            assert!(parse_request(raw.as_bytes()).is_err());
        }
        assert!(parse_request(&vec![b'x'; MAX_HEADERS + 1]).is_err());
    }
    #[test]
    fn authenticated_image_reads_use_private_regular_files() {
        use std::fs;
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "clipaste-http-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("image.png");
        let bytes = b"private PNG fixture";
        fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let latest = LatestImage::default();
        *latest.lock().unwrap() = Some(path.clone());
        let token = "a".repeat(64);
        let denied = route(
            Request {
                path: "/clipboard/image",
                bearer: None,
            },
            &latest,
            true,
            &token,
        );
        assert_eq!(denied.status, 401);
        let allowed = route(
            Request {
                path: "/clipboard/image",
                bearer: Some(&token),
            },
            &latest,
            true,
            &token,
        );
        assert_eq!(allowed.status, 200);
        assert_eq!(allowed.body, bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = dir.join("link.png");
            symlink(&path, &link).unwrap();
            *latest.lock().unwrap() = Some(link);
            assert_eq!(
                route(
                    Request {
                        path: "/clipboard/image",
                        bearer: Some(&token)
                    },
                    &latest,
                    true,
                    &token
                )
                .status,
                204
            );
            assert!(latest.lock().unwrap().is_none());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn markdown_is_authenticated_byte_exact_and_never_an_image() {
        use std::fs;
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "clipaste-md-http-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("document.md");
        let token = "a".repeat(64);
        let latest = LatestImage::default();
        for bytes in [
            "# 你好\r\n\n```bash\n$(touch should-never-run)\n```\n".as_bytes(),
            b"".as_slice(),
        ] {
            fs::write(&path, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            *latest.lock().unwrap() = Some(path.clone());
            assert_eq!(
                route(
                    Request {
                        path: "/clipboard/file",
                        bearer: None
                    },
                    &latest,
                    true,
                    &token
                )
                .status,
                401
            );
            let state = route(
                Request {
                    path: "/clipboard/type",
                    bearer: Some(&token),
                },
                &latest,
                true,
                &token,
            );
            assert_eq!(state.body, b"{\"type\":\"file\",\"format\":\"md\"}");
            let file = route(
                Request {
                    path: "/clipboard/file",
                    bearer: Some(&token),
                },
                &latest,
                true,
                &token,
            );
            assert_eq!(file.status, 200);
            assert_eq!(file.content_type, "text/markdown; charset=utf-8");
            assert_eq!(file.body, bytes);
            assert_eq!(
                route(
                    Request {
                        path: "/clipboard/image",
                        bearer: Some(&token)
                    },
                    &latest,
                    true,
                    &token
                )
                .status,
                204
            );
        }
        fs::write(&path, [0xff, 0xfe]).unwrap();
        assert_eq!(
            route(
                Request {
                    path: "/clipboard/file",
                    bearer: Some(&token)
                },
                &latest,
                true,
                &token
            )
            .status,
            404
        );
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(common::MAX_MARKDOWN_BYTES as u64 + 1)
            .unwrap();
        assert_eq!(
            route(
                Request {
                    path: "/clipboard/file",
                    bearer: Some(&token)
                },
                &latest,
                true,
                &token
            )
            .status,
            204
        );
        assert!(latest.lock().unwrap().is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn long_transfers_do_not_relax_unauthenticated_request_limits() {
        for content_type in ["image/png", "text/markdown; charset=utf-8"] {
            assert_eq!(
                response_timeout(&Response::new(200, content_type, vec![])),
                Duration::from_secs(180)
            );
        }
        for status in [200, 401, 404] {
            assert_eq!(
                response_timeout(&Response::new(status, "application/json", vec![])),
                HEADER_TIMEOUT
            );
        }
    }

    #[test]
    fn bounded_response_writes_handle_partial_writes_and_a_single_deadline() {
        struct Partial {
            bytes: Vec<u8>,
            calls: usize,
        }
        impl Write for Partial {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                let n = bytes.len().min(7);
                self.bytes.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let payload = vec![b'x'; 65537];
        let mut writer = Partial {
            bytes: vec![],
            calls: 0,
        };
        let deadline = Instant::now() + TRANSFER_TIMEOUT;
        let mut previous = TRANSFER_TIMEOUT;
        write_until(&mut writer, &payload, deadline, |_, remaining| {
            assert!(remaining <= previous);
            assert!(remaining > HEADER_TIMEOUT);
            previous = remaining;
            Ok(())
        })
        .unwrap();
        assert_eq!(writer.bytes, payload);
        assert!(writer.calls > 1);
        let calls = writer.calls;
        let error = write_until(
            &mut writer,
            b"not sent",
            Instant::now() - Duration::from_secs(1),
            |_, _| panic!("deadline must be checked before writing"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(writer.calls, calls);
    }

    #[test]
    fn connection_slots_are_released_on_worker_exit() {
        let count = Arc::new(AtomicUsize::new(1));
        drop(ConnectionSlot(count.clone()));
        assert_eq!(count.load(Ordering::Relaxed), 0);
    }
}
