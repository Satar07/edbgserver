use anyhow::Result;
use aya::{maps::RingBuf, programs::UProbe};
use clap::Parser;
use std::os::fd::AsFd;
use std::path::Path;

use gdbstub::stub::{DisconnectReason, GdbStub};
use log::{debug, error, info, warn};
use tokio::net::TcpListener;

use crate::{
    connection::TokioConnection, event::EdbgEventLoop, proc::find_process_by_binary,
    target::EdbgTarget,
};
mod connection;
mod event;
mod proc;
mod target;
mod utils;

#[derive(Debug, Parser)]
struct Cli {
    #[clap(short, long, default_value_t = 3333)]
    port: u32,

    // #[clap(long)]
    // pid: Option<u32>,
    #[clap(short, long, required = true)]
    binary: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Cli::parse();
    env_logger::init();

    // 1. 确定目标 PID
    // let target_file: PathBuf;
    // let target_pid = if let Some(p) = opt.pid {
    //     p
    // } else if let Some(ref bin) = opt.binary {
    //     // 简单的查找逻辑
    //     let procs = proc::find_process_by_binary(bin)?;
    //     if procs.is_empty() {
    //         anyhow::bail!("Process not found");
    //     }
    //     target_file = procs[0].exe_path.clone();
    //     procs[0].pid as u32
    // } else {
    //     anyhow::bail!("Please provide --pid or --binary");
    // };

    // info!("Targeting PID: {}", target_pid);

    // 2. 初始化 Aya
    let mut ebpf = init_aya();

    // 3. 加载 eBPF 程序
    let program: &mut UProbe = ebpf
        .program_mut("edbgserver")
        .unwrap()
        .try_into()
        .expect("Failed to convert eBPF program to UProbe");

    program.load().expect("Failed to load eBPF program");

    // 假设我们要 Hook 目标程序的某个函数，这里需要具体的二进制路径和符号/偏移
    // 实际使用中可能需要解析 ELF 或者由用户输入

    let target_path = Path::new(&opt.binary).canonicalize();
    let target_path = match target_path {
        Ok(p) => p,
        Err(e) => {
            error!(
                "Failed to canonicalize target binary path: {} \n maybe not exists target file",
                e
            );
            return Err(e.into());
        }
    };

    program
        .attach(
            "trigger_breakpoint",
            target_path.canonicalize()?,
            None,
            None,
        )
        .expect("Failed to attach eBPF program");

    // 4. 初始化 RingBuf
    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").expect("EVENTS map not found"))?;
    let ring_buf_fd = ring_buf.as_fd().try_clone_to_owned()?;
    let notifier =
        tokio::io::unix::AsyncFd::with_interest(ring_buf_fd, tokio::io::Interest::READABLE)?;

    // 5. 等待 GDB 连接
    let listen_addr = format!("0.0.0.0:{}", opt.port);
    let listener = TcpListener::bind(&listen_addr).await?;
    info!("Waiting for GDB connect on {}", listen_addr);
    let (stream, addr) = listener.accept().await?;
    info!("GDB connected from {}", addr);

    // 设置 TCP 使得 peek/read 不会永远阻塞，以便我们能轮询 eBPF
    // stream.set_nonblocking(true)?;

    // let connection: Box<dyn ConnectionExt<Error = std::io::Error>> = Box::new(stream);

    // 6. 初始化 Target 和 GDBStub
    let p = find_process_by_binary(&opt.binary)?;

    // 用第一个就行
    let target_pid = p[0].pid;

    let mut target = EdbgTarget::new(target_pid, ring_buf, notifier)?;

    // run_gdb_session(stream, target).await?;
    let connection = TokioConnection::new(stream);
    let gdb = GdbStub::new(connection);
    let result =
        tokio::task::spawn_blocking(move || gdb.run_blocking::<EdbgEventLoop>(&mut target)).await?;

    // // 7. 运行 Event Loop

    info!("Starting GDB Session...");
    match result {
        Ok(disconnect_reason) => match disconnect_reason {
            DisconnectReason::Disconnect => info!("GDB Disconnected"),
            DisconnectReason::TargetExited(code) => info!("Target exited with code {}", code),
            DisconnectReason::TargetTerminated(sig) => {
                info!("Target terminated with signal {}", sig)
            }
            DisconnectReason::Kill => {
                info!("GDB sent Kill command");
                // 可以在这里 kill -9 target_pid
            }
        },
        Err(e) => error!("GDBStub Error: {}", e),
    }

    // // 退出时恢复进程运行，否则进程会一直处于 SIGSTOP 状态
    // send_sigcont(target_pid as i32);

    Ok(())
}

fn init_aya() -> aya::Ebpf {
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
