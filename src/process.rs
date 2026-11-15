//! This process: its resources as Prometheus's client libraries name
//! them, and as Alloy's own (`alloy_resources_process_*`); and poll(2).

use crate::remote::Writer;
use std::fs;
use std::os::fd::RawFd;
use std::time::Duration;

/// Fields of /proc/self/stat after the command's closing parenthesis,
/// counted from the state as 0.
const UTIME: usize = 11;
const STIME: usize = 12;
const START: usize = 19;
const VSIZE: usize = 20;
const RSS: usize = 21;
const CLOCK_TICKS: f64 = 100.0;

pub fn collect(w: &mut Writer) {
    let text = fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let after = text.rfind(')').map_or("", |at| &text[at + 1..]);
    let fields: Vec<f64> = after
        .split_whitespace()
        .map(|f| f.parse().unwrap_or(0.0))
        .collect();
    let field = |index: usize| fields.get(index).copied().unwrap_or(0.0);
    // SAFETY: sysconf only reads a constant.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as f64;

    let start = crate::host::boot_time() + field(START) / CLOCK_TICKS;
    let values = [
        (
            "cpu_seconds_total",
            (field(UTIME) + field(STIME)) / CLOCK_TICKS,
        ),
        ("resident_memory_bytes", field(RSS) * page),
        ("virtual_memory_bytes", field(VSIZE)),
        ("start_time_seconds", start),
    ];
    for prefix in ["process_", "alloy_resources_process_"] {
        for (name, value) in values {
            w.add(&format!("{prefix}{name}"), &[], value);
        }
    }
    let fds = fs::read_dir("/proc/self/fd")
        .map(|d| d.count())
        .unwrap_or(0);
    w.add("process_open_fds", &[], fds as f64);
    // SAFETY: getrlimit fills the zeroed struct.
    let max = unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit);
        limit.rlim_cur
    };
    w.add("process_max_fds", &[], max as f64);
}

/// Which descriptors have data, an end or an error, after waiting at
/// most `timeout`; none if a signal came.
pub fn poll(fds: &[RawFd], timeout: Duration) -> Vec<bool> {
    let mut polled: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let millis =
        timeout.as_micros().div_ceil(1000).min(i32::MAX as u128) as i32;
    // SAFETY: the array lives across the call and its length is passed.
    let result = unsafe {
        libc::poll(polled.as_mut_ptr(), polled.len() as libc::nfds_t, millis)
    };
    let ready = libc::POLLIN | libc::POLLHUP | libc::POLLERR;
    polled
        .iter()
        .map(|p| result > 0 && p.revents & ready != 0)
        .collect()
}
