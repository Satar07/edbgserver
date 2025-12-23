use gdbstub::common::Signal;
use log::{debug, warn};
use std::io;

fn sys_tgkill(tgid: i32, tid: i32, sig: i32) -> io::Result<()> {
    debug!("Sending signal {} to tgid {} tid {}", sig, tgid, tid);
    let ret = unsafe { libc::syscall(libc::SYS_tgkill, tgid, tid, sig) };

    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn gdb_sig_to_libc(sig: &Signal) -> Option<i32> {
    match *sig {
        Signal::SIGHUP => Some(libc::SIGHUP),
        Signal::SIGINT => Some(libc::SIGINT),
        Signal::SIGQUIT => Some(libc::SIGQUIT),
        Signal::SIGILL => Some(libc::SIGILL),
        Signal::SIGTRAP => Some(libc::SIGTRAP),
        Signal::SIGABRT => Some(libc::SIGABRT),
        Signal::SIGBUS => Some(libc::SIGBUS),
        Signal::SIGFPE => Some(libc::SIGFPE),
        Signal::SIGKILL => Some(libc::SIGKILL),
        Signal::SIGUSR1 => Some(libc::SIGUSR1),
        Signal::SIGSEGV => Some(libc::SIGSEGV),
        Signal::SIGUSR2 => Some(libc::SIGUSR2),
        Signal::SIGPIPE => Some(libc::SIGPIPE),
        Signal::SIGALRM => Some(libc::SIGALRM),
        Signal::SIGTERM => Some(libc::SIGTERM),
        Signal::SIGCHLD => Some(libc::SIGCHLD),
        Signal::SIGCONT => Some(libc::SIGCONT),
        Signal::SIGSTOP => Some(libc::SIGSTOP),
        Signal::SIGTSTP => Some(libc::SIGTSTP),
        Signal::SIGTTIN => Some(libc::SIGTTIN),
        Signal::SIGTTOU => Some(libc::SIGTTOU),
        Signal::SIGURG => Some(libc::SIGURG),
        Signal::SIGXCPU => Some(libc::SIGXCPU),
        Signal::SIGXFSZ => Some(libc::SIGXFSZ),
        Signal::SIGVTALRM => Some(libc::SIGVTALRM),
        Signal::SIGPROF => Some(libc::SIGPROF),
        Signal::SIGWINCH => Some(libc::SIGWINCH),
        Signal::SIGIO => Some(libc::SIGIO),
        Signal::SIGPWR => Some(libc::SIGPWR),
        Signal::SIGSYS => Some(libc::SIGSYS),
        _ => None,
    }
}

/// if the disposition of the signal is "stop", "continue", or"terminate",
/// this action will affect the whole process. (that means it don't work :(
/// please someone tell me how to solve it...
pub fn send_sigcont_to_thread(pid: u32, tid: u32) {
    debug!("Sending SIGCONT to pid {} tid {}", pid, tid);
    if let Err(e) = sys_tgkill(pid as i32, tid as i32, libc::SIGCONT) {
        warn!("Failed to send SIGCONT to pid {} tid {}: {}", pid, tid, e);
    }
}

pub fn send_sig_to_thread(pid: u32, tid: u32, sig: &Signal) {
    debug!("Sending signal {:?} to pid {} tid {}", sig, pid, tid);
    if let Some(libc_sig) = gdb_sig_to_libc(sig) {
        if let Err(e) = sys_tgkill(pid as i32, tid as i32, libc_sig) {
            warn!(
                "Failed to send {:?} (libc: {}) to tgid {} tid {}: {}",
                sig, libc_sig, pid, tid, e
            );
        }
    } else {
        warn!(
            "Unsupported signal conversion for gdb signal: {:?} (tid: {})",
            sig, tid
        );
    }
}

fn sys_kill(pid: i32, sig: i32) -> io::Result<()> {
    debug!("Sending signal {} to pid {}", sig, pid);
    let ret = unsafe { libc::kill(pid, sig) };

    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn send_sig_to_process(pid: u32, sig: &Signal) {
    debug!("Sending signal {:?} to pid {}", sig, pid);
    if let Some(libc_sig) = gdb_sig_to_libc(sig) {
        if let Err(e) = sys_kill(pid as i32, libc_sig) {
            warn!(
                "Failed to send {:?} (libc: {}) to process {}: {}",
                sig, libc_sig, pid, e
            );
        }
    } else {
        warn!(
            "Unsupported signal conversion for gdb signal: {:?} (pid: {})",
            sig, pid
        );
    }
}
