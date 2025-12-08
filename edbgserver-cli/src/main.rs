use std::str::FromStr;

use anyhow::{Context, Result, bail};
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
    #[arg(long, default_value_t = 3333)]
    port: u32,
    #[arg(short, long)]
    pid: Option<u32>,
    #[arg(short, long)]
    target: String,
    #[arg(short, long)]
    break_point: BreakPointArg,
}

#[derive(Clone, Debug)]
struct BreakPointArg(u64);

impl FromStr for BreakPointArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parse_num = |input: &str| -> Result<u64, String> {
            let input = input.trim().to_lowercase();
            if let Some(stripped) = input.strip_prefix("0x") {
                u64::from_str_radix(stripped, 16)
                    .map_err(|_| format!("Invalid hex number: {}", input))
            } else {
                input
                    .parse::<u64>()
                    .map_err(|_| format!("Invalid number: {}", input))
            }
        };

        if let Ok(addr) = parse_num(s) {
            return Ok(BreakPointArg(addr));
        }

        Err("Breakpoint cannot be empty".to_string())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let opt = Cli::parse();
    debug!("start edbgserver at pid: {}", std::process::id());
    let ebpf = init_aya();

    // main target new
    let mut target = EdbgTarget::new(ebpf);
    target
        .attach_init_probe(opt.target.as_str(), opt.break_point.0, opt.pid)
        .context("Failed to attach init probe, make sure breakpoint and target is valid")?;

    println!(
        "Step 1: Waiting for Target Initial Trap at {}...",
        opt.target
    );

    match target.wait_for_init_trap().await {
        Ok(_) => info!("Target context captured successfully via eBPF"),
        Err(e) => bail!("Failed to catch initial trap: {}", e),
    }

    let listen_addr = format!("0.0.0.0:{}", opt.port);
    let listener = TcpListener::bind(&listen_addr)
        .await
        .context("Failed to bind TCP listener")?;

    println!(
        "Step 2: Target Ready. Waiting for GDB connect on {}...",
        listen_addr
    );

    let stream = match listener.accept().await {
        Ok((s, a)) => {
            info!("GDB connected from {}", a);
            s
        }
        Err(e) => bail!("Failed to accept GDB connection: {}", e),
    };

    let connection = TokioConnection::new(stream);
    let gdb = GdbStub::new(connection);

    // main run
    let result =
        tokio::task::spawn_blocking(move || gdb.run_blocking::<EdbgEventLoop>(&mut target))
            .await
            .expect("GDB Stub task panicked");
    match result {
        Ok(disconnect_reason) => match disconnect_reason {
            DisconnectReason::Disconnect => info!("GDB Disconnected"),
            DisconnectReason::TargetExited(code) => info!("Target exited with code {}", code),
            DisconnectReason::TargetTerminated(sig) => {
                info!("Target terminated with signal {}", sig)
            }
            DisconnectReason::Kill => {
                info!("GDB sent Kill command");
            }
        },
        Err(e) => error!("GDBStub Error: {}", e),
    }
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
