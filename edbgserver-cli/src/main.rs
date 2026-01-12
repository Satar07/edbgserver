use anyhow::{Context, Result, bail};
use clap::{
    Parser,
    builder::{
        Styles,
        styling::{AnsiColor, Effects},
    },
};
use clap_num::maybe_hex;
use gdbstub::stub::{DisconnectReason, GdbStubBuilder};
use log::{debug, error, info, warn};
use nix::sys::resource::{self, Resource, setrlimit};
use tokio::net::TcpListener;

use crate::{connection::TokioConnection, event::EdbgEventLoop, target::EdbgTarget};
mod connection;
mod event;
mod resolve_target;
mod target;
mod utils;
mod virtual_file;

fn get_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Green.on_default() | Effects::BOLD | Effects::UNDERLINE)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Cyan.on_default())
}

#[derive(Debug, Parser)]
#[command(
    version,
    about = "A GDB stub powered by eBPF.",
    styles = get_styles(),
    long_about = r#"An eBPF-based GDB Stub Server designed for analyzing running processes.

Operational Workflow:
  Step 1: Wait for Target Initial Trap
          The server installs a UProbe and waits for the target to hit the specified breakpoint.

  Step 2: Target Ready & GDB Connect
          Once the trap is caught, the server opens the TCP port and waits for a GDB client to connect.

Logging & Debugging:
  This tool uses `env_logger`. You can control log verbosity via the RUST_LOG environment variable.
  Available levels: error, warn, info, debug, trace.

  Example:
    RUST_LOG=debug ./edbgserver -t ./target -b 0x401000
    ./edbgserver -p io.cyril.supervipplayer -t libsupervipplayer.so -b 0x17E0
"#
)]
struct Cli {
    /// The TCP port where the GDB server will listen for incoming connections.
    #[arg(long, default_value_t = 3333)]
    port: u16,

    /// The Process ID (PID) of the target process to attach to.
    /// If omitted, the server will automatically attach to the first process that triggers the breakpoint in the specified binary.
    #[arg(short = 'P', long)]
    pid: Option<u32>,

    /// Path to the target binary or library.
    #[arg(short, long, value_hint = clap::ValueHint::FilePath)]
    target: String,

    /// [Android only] The package name of target application.
    #[arg(short = 'p', long)]
    package: Option<String>,

    /// The initial breakpoint address (virtual address).
    /// The server will set a UProbe at this location to intercept execution and wait for GDB.
    /// Supports hexadecimal (e.g., 0x400000) or decimal input.
    #[arg(short = 'b', long = "break", value_parser = maybe_hex::<u64>)]
    break_point: u64,

    /// Run the server in multi-threaded mode.
    #[arg(short = 'm', long)]
    multi_thread: bool,

    /// Disable filtering of memory maps when attaching to the target process.
    /// By default, the server filters out irrelevant memory maps to improve performance.
    #[arg(long = "no-filter")]
    map_filter_off: bool,

    /// force using uprobe implementation for single-step (perf by default)
    #[arg(long = "use-uprobe")]
    step_use_uprobe: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    debug!("start edbgserver at pid: {}", std::process::id());
    pretty_env_logger::init();
    let opt = Cli::parse();
    let (init_uprobe_file_path, init_uprobe_file_offset) =
        resolve_target::resolve_target(&opt.target, opt.package.as_deref(), opt.break_point)?;

    let ebpf = init_aya();

    // main target new
    let mut edbg_target = EdbgTarget::new(
        ebpf,
        opt.multi_thread,
        !opt.map_filter_off,
        opt.step_use_uprobe,
    );
    edbg_target
        .attach_init_probe(init_uprobe_file_path, init_uprobe_file_offset, opt.pid)
        .context("Failed to attach init probe, make sure breakpoint and target is valid")?;

    println!("Step 1: Waiting for Target Initial Trap...");

    match edbg_target.wait_for_init_trap().await {
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
    let gdb = GdbStubBuilder::new(connection)
        .packet_buffer_size(4096)
        .build()?;

    // main run
    let result =
        tokio::task::spawn_blocking(move || gdb.run_blocking::<EdbgEventLoop>(&mut edbg_target))
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
        Err(e) => warn!("GDBStub Error: {}", e),
    }
    Ok(())
}

fn init_aya() -> aya::Ebpf {
    pretty_env_logger::try_init().ok();
    if let Err(e) = setrlimit(
        Resource::RLIMIT_MEMLOCK,
        resource::RLIM_INFINITY,
        resource::RLIM_INFINITY,
    ) {
        error!("remove limit on locked memory failed: {}", e);
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
