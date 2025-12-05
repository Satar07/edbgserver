use clap::Parser;

use gdbstub::stub::{DisconnectReason, GdbStub};
use log::{debug, error, info, warn};
use tokio::net::TcpListener;

use crate::{connection::TokioConnection, event::EdbgEventLoop, target::EdbgTarget};
mod connection;
mod event;
mod target;
mod utils;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[clap(short, long, default_value_t = 3333)]
    port: u32,
    #[clap(long)]
    pid: Option<u32>,
    #[clap(short, long)]
    target: String,
    #[clap(short, long)]
    break_point: u64,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let opt = Cli::parse();
    debug!("start edbgserver at pid: {}", std::process::id());
    let ebpf = init_aya();

    // main target new
    let mut target = EdbgTarget::new(ebpf);
    target
        .attach_init_probe(opt.target.as_str(), opt.break_point, opt.pid)
        .expect("Failed to attach init probe");

    // connect gdb
    let listen_addr = format!("0.0.0.0:{}", opt.port);
    let listener = TcpListener::bind(&listen_addr)
        .await
        .expect("Failed to bind TCP listener");

    // wait for gdb connect and target initial trap
    println!(
        "Waiting for GDB connect on {} AND Target Initial Trap...",
        listen_addr
    );
    let tcp_task = async {
        info!("Waiting for GDB connection on {}...", listen_addr);
        let res = listener.accept().await;
        match &res {
            Ok((_, addr)) => info!("GDB connected from {}", addr),
            Err(e) => error!("Failed to accept GDB connection: {}", e),
        }
        res
    };
    let trap_task = async {
        info!("Waiting for Target to hit the initial breakpoint...");
        let res = target.wait_for_init_trap().await;
        match &res {
            Ok(_) => info!("Target context captured successfully via eBPF"),
            Err(e) => error!("Failed to catch initial trap: {}", e),
        }
        res
    };
    let (tcp_res, trap_res) = tokio::join!(tcp_task, trap_task);
    let (stream, addr) = tcp_res.expect("Failed to accept connection");
    info!("GDB connected from {}", addr);
    trap_res.expect("Failed to catch initial trap");

    let connection = TokioConnection::new(stream);
    let gdb = GdbStub::new(connection);

    // main run
    let result =
        tokio::task::spawn_blocking(move || gdb.run_blocking::<EdbgEventLoop>(&mut target))
            .await
            .expect("GDB Stub task panicked");
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
