//! Delivering a named `Signal` (wsh 0x14) to the process group of a channel.
//!
//! The wire says "a signal to the process group associated with a channel".
//! Names are accepted as `INT`, `SIGINT` or `int`; only the ones in
//! [`parse_signal`] are delivered, anything else is ignored (and logged), so a
//! client cannot use the message for anything an ordinary job-control signal
//! would not do.

/// Map a wire name to a signal number, or `None` for a name this server does
/// not deliver.
#[cfg(unix)]
pub fn parse_signal(name: &str) -> Option<i32> {
    let n = name.trim().to_ascii_uppercase();
    let n = n.strip_prefix("SIG").unwrap_or(&n);
    Some(match n {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "TERM" => libc::SIGTERM,
        "KILL" => libc::SIGKILL,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "WINCH" => libc::SIGWINCH,
        "CONT" => libc::SIGCONT,
        "STOP" => libc::SIGSTOP,
        "TSTP" => libc::SIGTSTP,
        "ALRM" => libc::SIGALRM,
        _ => return None,
    })
}

#[cfg(not(unix))]
pub fn parse_signal(_name: &str) -> Option<i32> {
    None
}

/// Send `sig` to the process group `pgid` (and, failing that, to the process
/// `pid` itself).
#[cfg(unix)]
pub fn kill_group(pgid: i32, pid: i32, sig: i32) -> bool {
    // SAFETY: plain syscalls with integers; a stale id can at worst miss.
    unsafe {
        if pgid > 1 && libc::kill(-pgid, sig) == 0 {
            return true;
        }
        pid > 1 && libc::kill(pid, sig) == 0
    }
}

#[cfg(not(unix))]
pub fn kill_group(_pgid: i32, _pid: i32, _sig: i32) -> bool {
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn names_with_or_without_the_prefix_in_any_case() {
        assert_eq!(parse_signal("INT"), Some(libc::SIGINT));
        assert_eq!(parse_signal("SIGINT"), Some(libc::SIGINT));
        assert_eq!(parse_signal("sigterm"), Some(libc::SIGTERM));
        assert_eq!(parse_signal(" HUP "), Some(libc::SIGHUP));
    }

    #[test]
    fn unknown_names_are_not_delivered() {
        for n in ["", "SIG", "SEGV", "9", "INT; rm -rf /", "SIGSIGINT"] {
            assert_eq!(parse_signal(n), None, "{n:?}");
        }
    }
}
