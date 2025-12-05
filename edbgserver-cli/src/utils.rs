use nix::{
    sys::signal::{self},
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
