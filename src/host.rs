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

/// When the host booted, in seconds since the epoch.
pub fn boot_time() -> f64 {
    let stat = std::fs::read_to_string(path("/proc/stat")).unwrap_or_default();
    let line = stat.lines().find_map(|l| l.strip_prefix("btime "));
    line.and_then(|t| t.trim().parse().ok()).unwrap_or(0.0)
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

/// This host's name, as Alloy's `constants.hostname` gives it.
pub fn hostname() -> String {
    let mut name = [0u8; 256];
    // SAFETY: the buffer is writable and its length is given.
    let ok = unsafe { libc::gethostname(name.as_mut_ptr().cast(), name.len()) };
    if ok != 0 {
        return String::new();
    }
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    String::from_utf8_lossy(&name[..end]).into_owned()
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
