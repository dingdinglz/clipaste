use crate::common;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::{DeleteObject, GetObjectW, BITMAP};
use windows_sys::Win32::System::DataExchange::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const WM_CLIPBOARDUPDATE: u32 = 0x031D;

// Standard clipboard format constants
const CF_BITMAP: u32 = 2;
const CF_UNICODETEXT: u32 = 13;
const CF_DIB: u32 = 8;
const CF_HDROP: u32 = 15;

static mut LAST_SEQ: u32 = 0;

/// Global shared state for the Win32 callback (wnd_proc can't capture closures)
static LATEST: OnceLock<common::LatestImage> = OnceLock::new();
/// Set once in `run`, before the listener can deliver any clipboard update.
static SERVER_ONLY: AtomicBool = AtomicBool::new(false);

/// Check if clipboard has image data but no text or file drop
fn is_image_only_clipboard() -> bool {
    unsafe {
        let has_dib = IsClipboardFormatAvailable(CF_DIB) != 0;
        let has_bitmap = IsClipboardFormatAvailable(CF_BITMAP) != 0;
        let has_text = IsClipboardFormatAvailable(CF_UNICODETEXT) != 0;
        let has_hdrop = IsClipboardFormatAvailable(CF_HDROP) != 0;

        (has_dib || has_bitmap) && !has_text && !has_hdrop
    }
}

/// Read CF_DIB data from clipboard and convert to PNG
fn read_clipboard_as_png(expected_seq: u32) -> Option<Vec<u8>> {
    unsafe {
        if OpenClipboard(ptr::null_mut() as HWND) == 0 {
            return None;
        }

        let result = (|| {
            if GetClipboardSequenceNumber() != expected_seq {
                return None;
            }
            let handle = GetClipboardData(CF_DIB) as *mut u8;
            if handle.is_null() {
                return None;
            }

            let size = GlobalSize(handle as *mut _);
            if size == 0 || size > common::MAX_IMAGE_BYTES {
                return None;
            }
            let ptr = GlobalLock(handle as *mut _);
            if ptr.is_null() {
                return None;
            }

            let data = std::slice::from_raw_parts(ptr as *const u8, size);
            let dib_data = data.to_vec();

            GlobalUnlock(handle as *mut _);
            Some(dib_data)
        })();

        CloseClipboard();

        let dib_data = result?;
        if GetClipboardSequenceNumber() != expected_seq {
            return None;
        }
        let png = common::dib_to_png(&dib_data)?;
        (GetClipboardSequenceNumber() == expected_seq).then_some(png)
    }
}

struct ClipboardCopy {
    format: u32,
    handle: HANDLE,
    bitmap: bool,
}

impl Drop for ClipboardCopy {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                if self.bitmap {
                    DeleteObject(self.handle);
                } else {
                    GlobalFree(self.handle);
                }
            }
        }
    }
}

fn global_copy(format: u32, bytes: &[u8]) -> Option<ClipboardCopy> {
    if bytes.is_empty() || bytes.len() > common::MAX_IMAGE_BYTES {
        return None;
    }
    unsafe {
        let handle = GlobalAlloc(GMEM_MOVEABLE, bytes.len());
        if handle.is_null() {
            return None;
        }
        let copy = ClipboardCopy {
            format,
            handle,
            bitmap: false,
        };
        let destination = GlobalLock(handle);
        if destination.is_null() {
            return None;
        }
        ptr::copy_nonoverlapping(bytes.as_ptr(), destination as *mut u8, bytes.len());
        GlobalUnlock(handle);
        Some(copy)
    }
}

/// Snapshot every available representation before taking ownership. Special
/// GDI/owner-display/private formats cannot be treated as HGLOBAL bytes. Refuse
/// the rewrite if one cannot be preserved, rather than silently dropping it.
fn snapshot_clipboard() -> Option<Vec<ClipboardCopy>> {
    let mut copies = Vec::new();
    let mut total = 0usize;
    let mut format = 0;
    unsafe {
        loop {
            SetLastError(0);
            format = EnumClipboardFormats(format);
            if format == 0 {
                return (GetLastError() == 0).then_some(copies);
            }
            if copies.len() >= 256 {
                return None;
            }
            let handle = GetClipboardData(format);
            if handle.is_null() {
                return None;
            }
            let copy = if format == CF_BITMAP || format == 0x82 {
                let mut bitmap: BITMAP = std::mem::zeroed();
                if GetObjectW(
                    handle,
                    std::mem::size_of::<BITMAP>() as i32,
                    &mut bitmap as *mut _ as *mut _,
                ) == 0
                {
                    return None;
                }
                let width = bitmap.bmWidth.unsigned_abs() as usize;
                let height = bitmap.bmHeight.unsigned_abs() as usize;
                if width == 0 || height == 0 || width > 16384 || height > 16384 {
                    return None;
                }
                let size = width
                    .checked_mul(4)?
                    .max(bitmap.bmWidthBytes.unsigned_abs() as usize)
                    .checked_mul(height)?;
                if size > common::MAX_IMAGE_BYTES {
                    return None;
                }
                total = total.checked_add(size)?;
                if total > 128 * 1024 * 1024 {
                    return None;
                }
                let copy = CopyImage(handle, IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION);
                if copy.is_null() {
                    return None;
                }
                ClipboardCopy {
                    format,
                    handle: copy,
                    bitmap: true,
                }
            } else {
                // Standard memory formats and registered formats use HGLOBAL.
                // Refuse palettes, metafiles, owner-display and private GDI data.
                if !matches!(
                    format,
                    1 | 7 | 8 | 13 | 15 | 16 | 17 | 0x81 | 0xc000..=0xffff
                ) {
                    return None;
                }
                let size = GlobalSize(handle);
                total = total.checked_add(size)?;
                if size == 0 || size > common::MAX_IMAGE_BYTES || total > 128 * 1024 * 1024 {
                    return None;
                }
                let source = GlobalLock(handle);
                if source.is_null() {
                    return None;
                }
                let copy = global_copy(
                    format,
                    std::slice::from_raw_parts(source as *const u8, size),
                );
                GlobalUnlock(handle);
                copy?
            };
            copies.push(copy);
        }
    }
}

fn write_path_to_clipboard(
    hwnd: HWND,
    path: &str,
    png_data: &[u8],
    expected_seq: u32,
) -> Option<u32> {
    unsafe {
        if OpenClipboard(hwnd) == 0 {
            return None;
        }
        let result = (|| {
            if GetClipboardSequenceNumber() != expected_seq {
                return None;
            }
            let Some(mut copies) = snapshot_clipboard() else {
                common::log(
                    "skipped local normalization: cannot safely preserve every clipboard format",
                );
                return Some(expected_seq);
            };
            let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let wide_bytes = std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2);
            copies.push(global_copy(CF_UNICODETEXT, wide_bytes)?);
            let png_format_name: Vec<u16> = "PNG\0".encode_utf16().collect();
            let png_format = RegisterClipboardFormatW(png_format_name.as_ptr());
            if png_format == 0 {
                return None;
            }
            if !copies.iter().any(|copy| copy.format == png_format) {
                copies.push(global_copy(png_format, png_data)?);
            }
            if GetClipboardSequenceNumber() != expected_seq {
                return None;
            }
            // A real listener HWND is required: EmptyClipboard with a NULL
            // owner makes SetClipboardData fail.
            if EmptyClipboard() == 0 {
                return None;
            }
            let mut complete = true;
            for copy in &mut copies {
                if SetClipboardData(copy.format, copy.handle).is_null() {
                    complete = false;
                } else {
                    copy.handle = ptr::null_mut(); // ownership transferred
                }
            }
            // Capture under the lock so a new copy after CloseClipboard cannot
            // be mistaken for the event generated by our normalization.
            let sequence = GetClipboardSequenceNumber();
            if !complete {
                common::log("failed to republish a clipboard format");
            }
            Some(sequence)
        })();
        CloseClipboard();
        result.filter(|seq| GetClipboardSequenceNumber() == *seq)
    }
}

fn normalize(
    hwnd: HWND,
    latest: &common::LatestImage,
    server_only: bool,
    expected_seq: u32,
) -> Option<u32> {
    if unsafe { GetClipboardSequenceNumber() } != expected_seq || !is_image_only_clipboard() {
        return None;
    }

    let png_data = match read_clipboard_as_png(expected_seq) {
        Some(d) => d,
        None => {
            common::log("failed to read clipboard image as PNG (or clipboard changed)");
            return None;
        }
    };

    let file_path = common::save_png_to_temp(&png_data)?;
    if unsafe { GetClipboardSequenceNumber() } != expected_seq {
        return None;
    }

    let filename = file_path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    let final_seq = if server_only {
        common::log(&format!(
            "staged {filename} ({} bytes) for remote paste",
            png_data.len()
        ));
        expected_seq
    } else {
        let own_seq =
            write_path_to_clipboard(hwnd, &file_path.to_string_lossy(), &png_data, expected_seq)?;
        common::log(&format!("normalized {filename} ({} bytes)", png_data.len()));
        own_seq
    };
    if unsafe { GetClipboardSequenceNumber() } != final_seq {
        return None;
    }
    if let Ok(mut guard) = latest.lock() {
        *guard = Some(file_path);
    }
    Some(final_seq)
}

fn accept_sequence(latest: &common::LatestImage, last: &mut u32, sequence: u32) -> bool {
    if sequence == *last {
        return false;
    }
    *last = sequence;
    // Every genuine update invalidates the old image, including text/empty.
    if let Ok(mut staged) = latest.lock() {
        *staged = None;
    }
    true
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CLIPBOARDUPDATE => {
            let seq = GetClipboardSequenceNumber();
            // Work on a local copy to avoid references to mutable statics. Own
            // normalization records its sequence before queued events dispatch.
            let mut last = LAST_SEQ;
            if let Some(latest) = LATEST.get() {
                if accept_sequence(latest, &mut last, seq) {
                    LAST_SEQ = last;
                    if let Some(own_seq) =
                        normalize(hwnd, latest, SERVER_ONLY.load(Ordering::Relaxed), seq)
                    {
                        LAST_SEQ = own_seq;
                    }
                }
            }
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub fn run(latest: common::LatestImage, server_only: bool) {
    LATEST.set(latest).expect("LATEST already initialized");
    SERVER_ONLY.store(server_only, Ordering::Relaxed);
    if let Err(e) = common::ensure_temp_dir() {
        common::log(&format!("Cannot initialize PNG cache: {e}"));
        std::process::exit(1);
    }
    common::log(&format!(
        "v{} started (pid {})",
        common::VERSION,
        std::process::id()
    ));
    if server_only {
        common::log(
            "server-only mode: images are served over HTTP; the clipboard is never rewritten",
        );
    }

    unsafe {
        let class_name: Vec<u16> = "clipaste_hidden\0".encode_utf16().collect();
        let hinstance = GetModuleHandleW(ptr::null());

        let wc = WNDCLASSW {
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinstance,
            lpszClassName: class_name.as_ptr(),
            style: 0,
            cbClsExtra: 0,
            cbWndExtra: 0,
            hIcon: ptr::null_mut(),
            hCursor: ptr::null_mut(),
            hbrBackground: ptr::null_mut(),
            lpszMenuName: ptr::null(),
        };

        RegisterClassW(&wc);

        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            class_name.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            ptr::null_mut() as HMENU,
            hinstance,
            ptr::null(),
        );

        if hwnd.is_null() {
            common::log("failed to create hidden window");
            std::process::exit(1);
        }

        if AddClipboardFormatListener(hwnd) == 0 {
            common::log("failed to register clipboard listener");
            std::process::exit(1);
        }

        common::log("clipboard listener registered (event-driven, no polling)");
        LAST_SEQ = GetClipboardSequenceNumber();
        if let Some(latest) = LATEST.get() {
            if let Some(seq) = normalize(hwnd, latest, server_only, LAST_SEQ) {
                LAST_SEQ = seq;
            }
        }

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, ptr::null_mut() as HWND, 0, 0) > 0 {
            DispatchMessageW(&msg);
        }

        RemoveClipboardFormatListener(hwnd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn genuine_text_or_empty_update_clears_but_self_sequence_does_not() {
        let latest = Arc::new(Mutex::new(Some("fixture.png".into())));
        let mut last = 10;
        assert!(!accept_sequence(&latest, &mut last, 10));
        assert!(latest.lock().unwrap().is_some());
        assert!(accept_sequence(&latest, &mut last, 11));
        assert!(latest.lock().unwrap().is_none());
        // Normalization records its final sequence before its queued event.
        *latest.lock().unwrap() = Some("normalized.png".into());
        last = 12;
        assert!(!accept_sequence(&latest, &mut last, 12));
        assert!(latest.lock().unwrap().is_some());
        assert!(accept_sequence(&latest, &mut last, 13));
        assert!(latest.lock().unwrap().is_none());
    }

    #[test]
    fn wrapped_sequences_are_still_genuine_updates() {
        let latest = Arc::new(Mutex::new(Some("fixture.png".into())));
        let mut last = u32::MAX;
        assert!(accept_sequence(&latest, &mut last, 0));
        assert!(latest.lock().unwrap().is_none());
    }
}
