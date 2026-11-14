//! Where the host's file systems are: `/`, or in a container the
//! directory the host's root is bind-mounted at (setting `root`), as
//! node_exporter's `--path.rootfs`. /proc and /sys are read there too:
//! in an LXC, lxcfs gives the guest's own memory and CPUs only to
//! /proc in the guest's mount namespace.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::OnceLock;

static ROOT: OnceLock<PathBuf> = OnceLock::new();

/// Set once, before anything reads the host.
pub fn set_root(root: PathBuf) {
    let _ = ROOT.set(root);
}

/// A path of the host's (`/proc/stat`) where this process sees it.
pub fn path(path: &str) -> PathBuf {
    match ROOT.get() {
        Some(root) => root.join(path.trim_start_matches('/')),
        None => PathBuf::from(path),
    }
}

/// statvfs of a host's mount point.
pub fn statvfs(path: &str) -> Option<libc::statvfs> {
    let path = CString::new(self::path(path).as_os_str().as_bytes()).ok()?;
    // SAFETY: a NUL-terminated path and a zeroed struct for the result.
    unsafe {
        let mut stats: libc::statvfs = std::mem::zeroed();
        (libc::statvfs(path.as_ptr(), &mut stats) == 0).then_some(stats)
    }
}

/// Mount tables write space, tab, newline and backslash as `\040`...
pub fn unescape(field: &str) -> String {
    if !field.contains('\\') {
        return field.to_owned();
    }
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes.get(i + 1..i + 4).and_then(|digits| {
            let digits = std::str::from_utf8(digits).ok()?;
            u8::from_str_radix(digits, 8).ok()
        });
        match (bytes[i], octal) {
            (b'\\', Some(byte)) => {
                out.push(byte);
                i += 4;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescapes_mount_points() {
        assert_eq!(unescape("/mnt/a\\040b"), "/mnt/a b");
        assert_eq!(unescape("/plain"), "/plain");
        assert_eq!(unescape("/odd\\x"), "/odd\\x");
    }
}
