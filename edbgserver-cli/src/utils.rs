use gdbstub::common::Signal;
use nix::{
    sys::signal::{self, kill},
    unistd::Pid,
};

pub fn send_sigcont(pid: u32) {
    let pid = Pid::from_raw(pid as i32);
    signal::kill(pid, signal::SIGCONT).expect("Failed to send SIGCONT");
}

pub fn send_sigstop(pid: u32) {
    let pid = Pid::from_raw(pid as i32);
    signal::kill(pid, signal::SIGSTOP).expect("Failed to send SIGSTOP");
}

pub fn send_sig(tid: u32, sig: &Signal) {
    let tid = Pid::from_raw(tid as i32);
    match *sig {
        Signal::SIGHUP => kill(tid, signal::SIGHUP).unwrap(),
        Signal::SIGINT => kill(tid, signal::SIGINT).unwrap(),
        Signal::SIGQUIT => kill(tid, signal::SIGQUIT).unwrap(),
        Signal::SIGILL => kill(tid, signal::SIGILL).unwrap(),
        Signal::SIGTRAP => kill(tid, signal::SIGTRAP).unwrap(),
        Signal::SIGABRT => kill(tid, signal::SIGABRT).unwrap(),
        Signal::SIGFPE => kill(tid, signal::SIGFPE).unwrap(),
        Signal::SIGKILL => kill(tid, signal::SIGKILL).unwrap(),
        Signal::SIGBUS => kill(tid, signal::SIGBUS).unwrap(),
        Signal::SIGSEGV => kill(tid, signal::SIGSEGV).unwrap(),
        Signal::SIGSYS => kill(tid, signal::SIGSYS).unwrap(),
        Signal::SIGPIPE => kill(tid, signal::SIGPIPE).unwrap(),
        Signal::SIGALRM => kill(tid, signal::SIGALRM).unwrap(),
        Signal::SIGTERM => kill(tid, signal::SIGTERM).unwrap(),
        Signal::SIGURG => kill(tid, signal::SIGURG).unwrap(),
        Signal::SIGSTOP => kill(tid, signal::SIGSTOP).unwrap(),
        Signal::SIGTSTP => kill(tid, signal::SIGTSTP).unwrap(),
        Signal::SIGCONT => kill(tid, signal::SIGCONT).unwrap(),
        Signal::SIGCHLD => kill(tid, signal::SIGCHLD).unwrap(),
        Signal::SIGTTIN => kill(tid, signal::SIGTTIN).unwrap(),
        Signal::SIGTTOU => kill(tid, signal::SIGTTOU).unwrap(),
        Signal::SIGIO => kill(tid, signal::SIGIO).unwrap(),
        Signal::SIGXCPU => kill(tid, signal::SIGXCPU).unwrap(),
        Signal::SIGXFSZ => kill(tid, signal::SIGXFSZ).unwrap(),
        Signal::SIGVTALRM => kill(tid, signal::SIGVTALRM).unwrap(),
        Signal::SIGPROF => kill(tid, signal::SIGPROF).unwrap(),
        Signal::SIGWINCH => kill(tid, signal::SIGWINCH).unwrap(),
        Signal::SIGUSR1 => kill(tid, signal::SIGUSR1).unwrap(),
        Signal::SIGUSR2 => kill(tid, signal::SIGUSR2).unwrap(),
        Signal::SIGPWR => kill(tid, signal::SIGPWR).unwrap(),
        Signal::SIGPOLL => kill(tid, signal::SIGPOLL).unwrap(),
        _ => panic!("Unsupported signal"),
    }
}
