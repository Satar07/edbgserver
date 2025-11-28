use std::{
    path::Path,
    process::{Command, Stdio},
    thread::sleep,
    time::Duration,
};

use aya::{maps::RingBuf, programs::UProbe};
use edbgserver_common::DataT;
use log::{debug, warn};
use serial_test::serial;

fn init_edbg_server() -> aya::Ebpf {
    env_logger::try_init().ok();
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/edbgserver"
    )))
    .expect("Failed to load eBPF program");
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)
                    .expect("Failed to create AsyncFd for logger");
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    ebpf
}

#[tokio::test]
#[serial]
async fn test_breakpoint_signal() {
    // create test target process
    let target_prog = Path::new("./tests/test_target/test_target");
    #[allow(clippy::zombie_processes)]
    let mut child = Command::new(target_prog)
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn target");
    let target_pid = child.id();
    println!("Test target pid: {}", target_pid);
    sleep(Duration::from_millis(200));
    let mut ebpf = init_edbg_server();
    // Attach uprobe to the target function
    let program: &mut UProbe = ebpf
        .program_mut("edbgserver")
        .unwrap()
        .try_into()
        .expect("Failed to convert eBPF program to UProbe");
    program.load().expect("Failed to load eBPF program");
    program
        .attach(
            "trigger_breakpoint",
            "/home/cyril/dev/learn/rust/edbgserver/edbgserver/edbgserver/tests/test_target/test_target",
            None,
            None,
        )
        .expect("Failed to attach eBPF program");
    sleep(Duration::from_secs(1));
    // should stop the target process when the function is called
    let status = read_process_state(target_pid);
    assert!(status.to_uppercase() == "T", "Process should be stop");
    // send SIGCONT to continue the process
    unsafe {
        libc::kill(target_pid as i32, libc::SIGCONT);
    }
    let after_status = read_process_state(target_pid);
    // program should have continued
    assert!(
        after_status.to_uppercase() != "T",
        "Process should not be stop anymore"
    );
    let _ = child.kill();
}

#[tokio::test]
#[serial]
async fn test_breakpoint_ret_info() {
    // create test target process
    let target_prog = Path::new("./tests/test_target/test_target");
    #[allow(clippy::zombie_processes)]
    let mut child = Command::new(target_prog)
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn target");
    let target_pid = child.id();
    println!("Test target pid: {}", target_pid);
    sleep(Duration::from_millis(200));
    let mut ebpf = init_edbg_server();
    // 拿到event map

    // Attach uprobe to the target function
    let program: &mut UProbe = ebpf
        .program_mut("edbgserver")
        .unwrap()
        .try_into()
        .expect("Failed to convert eBPF program to UProbe");
    program.load().expect("Failed to load eBPF program");

    let _link = program
        .attach(
            "trigger_breakpoint",
            "/home/cyril/dev/learn/rust/edbgserver/edbgserver/edbgserver/tests/test_target/test_target",
            None,
            None,
        )
        .expect("Failed to attach eBPF program");
    sleep(Duration::from_secs(1));
    // should stop the target process when the function is called
    let status = read_process_state(target_pid);
    assert!(status.to_uppercase() == "T", "Process should be stop");

    let events_map = ebpf.map_mut("EVENTS").expect("Failed to find EVENTS map");
    let mut events =
        RingBuf::try_from(events_map).expect("Failed to create RingBuf from EVENTS map");

    // 从 EVENTS 里面拿数据
    if let Some(event) = events.next() {
        let data_ptr = event.as_ptr() as *const DataT;
        let data = unsafe { &*data_ptr }; // unsafe: dereference raw pointer to struct

        println!("Received event from RingBuf:");
        println!("  PID: {}", data.pid);
        println!("  PC:  0x{:x}", data.pc);
        println!("  SP:  0x{:x}", data.sp);

        // 验证 PID 是否匹配
        assert_eq!(data.pid, target_pid, "RingBuf PID matches target PID");

        // 验证 PC (程序计数器) 不应该为 0
        assert!(data.pc > 0, "PC should be non-zero");

        // 验证 SP (栈指针) 不应该为 0
        assert!(data.sp > 0, "SP should be non-zero");

        // 验证寄存器数组不全是 0 (至少有一些通用寄存器会被使用)
        let regs_sum: u64 = data.regs.iter().sum();
        assert!(regs_sum > 0, "Registers shouldn't be all empty");
    }
    let _ = child.kill();
}

fn read_process_state(pid: u32) -> String {
    let path = format!("/proc/{}/stat", pid);
    let content = std::fs::read_to_string(path).unwrap_or_default();
    content.split_whitespace().nth(2).unwrap_or("?").to_string()
}
