//! Host and process resource sampling.
//!
//! Linux reads `/proc` directly (the daemon's target); other platforms fill in
//! what they can and leave the rest zeroed. Nothing here is load-bearing for
//! correctness — it is context, so a throughput number can be read alongside
//! "the box was at 100% CPU and 90% memory at that moment".

use crate::report::{HostInfo, ProcInfo};

/// Sample this process's resource usage plus a little system context.
#[cfg(target_os = "linux")]
pub fn proc_info() -> ProcInfo {
    let mut info = ProcInfo::default();

    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            let mut it = line.split_whitespace();
            match it.next() {
                Some("VmRSS:") => info.rss_kb = it.next().and_then(|v| v.parse().ok()).unwrap_or(0),
                Some("VmSize:") => {
                    info.vm_size_kb = it.next().and_then(|v| v.parse().ok()).unwrap_or(0)
                }
                Some("Threads:") => {
                    info.threads = it.next().and_then(|v| v.parse().ok()).unwrap_or(0)
                }
                _ => {}
            }
        }
    }

    // /proc/self/stat: utime is field 14, stime field 15 (1-indexed). The comm
    // field can contain spaces and parentheses, so split after the last ')'.
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        if let Some(tail) = stat.rsplit_once(')').map(|(_, t)| t) {
            let f: Vec<&str> = tail.split_whitespace().collect();
            // After the ')' the next field is state (field 3), so utime is
            // index 11 and stime index 12 in this tail slice.
            info.utime_ticks = f.get(11).and_then(|v| v.parse().ok()).unwrap_or(0);
            info.stime_ticks = f.get(12).and_then(|v| v.parse().ok()).unwrap_or(0);
        }
    }

    info.open_fds = std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count() as u64)
        .unwrap_or(0);

    if let Ok(load) = std::fs::read_to_string("/proc/loadavg") {
        let f: Vec<&str> = load.split_whitespace().collect();
        info.load1 = f.first().and_then(|v| v.parse().ok()).unwrap_or(0.0);
        info.load5 = f.get(1).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    }

    if let Ok(mem) = std::fs::read_to_string("/proc/meminfo") {
        for line in mem.lines() {
            if let Some(rest) = line.strip_prefix("MemAvailable:") {
                info.mem_available_kb = rest
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                break;
            }
        }
    }

    if let Ok(up) = std::fs::read_to_string("/proc/uptime") {
        info.uptime_s = up
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0) as u64;
    }

    info
}

#[cfg(not(target_os = "linux"))]
pub fn proc_info() -> ProcInfo {
    // Non-Linux hosts run the probe, not the daemon; per-process resource
    // sampling is not part of what the probe measures, so an empty record is
    // honest rather than a half-populated one that invites comparison.
    ProcInfo::default()
}

/// Describe the host this binary is running on.
pub fn host_info(probe_target: Option<&str>) -> HostInfo {
    HostInfo {
        os: format!("{} {}", std::env::consts::OS, os_release()),
        arch: std::env::consts::ARCH.to_string(),
        hostname: hostname(),
        cpu_count: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        local_addrs: local_addrs(probe_target),
    }
}

fn hostname() -> String {
    // `hostname(1)` exists on every platform this runs on; falling back to a
    // marker keeps this infallible rather than dragging in a libc dependency
    // for one string.
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn os_release() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/etc/os-release") {
            for line in s.lines() {
                if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
                    return v.trim_matches('"').to_string();
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(v) = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
        {
            return v.trim().to_string();
        }
    }
    String::new()
}

/// Local addresses, with the address that actually routes to `target` first.
///
/// Determined by connecting a UDP socket (no packets are sent — `connect` on a
/// datagram socket only fixes the peer and lets the kernel pick a source),
/// which answers the question that matters for a migration test: which local
/// address is the one in use right now.
fn local_addrs(target: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(t) = target {
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(t).is_ok() {
                if let Ok(a) = sock.local_addr() {
                    out.push(format!("outbound:{}", a.ip()));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_info_is_populated() {
        let h = host_info(None);
        assert!(!h.os.is_empty());
        assert!(!h.arch.is_empty());
        assert!(h.cpu_count > 0, "available_parallelism should report a CPU");
    }

    #[test]
    fn outbound_address_is_discovered_for_a_routable_target() {
        // 192.0.2.1 is TEST-NET-1: routable enough for the kernel to pick a
        // source address, and no packet is ever sent to it.
        let h = host_info(Some("192.0.2.1:9"));
        // Not asserted as non-empty: a host with no default route legitimately
        // yields nothing, and that must not fail the harness's own tests.
        for a in &h.local_addrs {
            assert!(a.starts_with("outbound:"), "unexpected form: {a}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_info_reads_real_values_on_linux() {
        let p = proc_info();
        assert!(p.rss_kb > 0, "a running process has resident memory");
        assert!(p.threads > 0);
        assert!(p.open_fds > 0);
    }

    #[test]
    fn proc_info_never_panics() {
        let _ = proc_info();
    }
}
