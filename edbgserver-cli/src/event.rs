use edbgserver_common::DataT;
use gdbstub::{
    common::Signal,
    stub::{
        SingleThreadStopReason,
        run_blocking::{self},
    },
};

use gdbstub::target::Target;

use crate::{connection::TokioConnection, target::EdbgTarget, utils::send_sigstop};
use tokio::{io::AsyncReadExt, runtime::Handle};
pub struct EdbgEventLoop {
    // pub ring_buf: tokio::io::unix::AsyncFd<aya::maps::RingBuf<&'a mut aya::maps::MapData>>,
}

impl run_blocking::BlockingEventLoop for EdbgEventLoop {
    type Target = EdbgTarget;
    type Connection = TokioConnection;
    type StopReason = SingleThreadStopReason<u64>;

    // -------------------------------------------------------------------------
    // 等待停止原因 (核心逻辑)
    // -------------------------------------------------------------------------
    fn wait_for_stop_reason(
        target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> Result<
        run_blocking::Event<Self::StopReason>,
        run_blocking::WaitForStopReasonError<<Self::Target as Target>::Error, std::io::Error>,
    > {
        Handle::current().block_on(async {
            loop {
                tokio::select! {
                    biased;
                    res = conn.stream.read_u8() => {
                        match res {
                            Ok(byte) => return Ok(run_blocking::Event::IncomingData(byte)),
                            Err(e) => return Err(run_blocking::WaitForStopReasonError::Connection(e)),
                        }
                    }

                    guard_res = target.notifier.readable() => {
                        let mut guard = match guard_res {
                            Ok(g) => g,
                            Err(e) => return Err(run_blocking::WaitForStopReasonError::Connection(e)),
                        };


                        let mut event_received = false;

                        while let Some(item) = target.ring_buf.next() {
                            // 安全地将字节转换为 DataT 结构
                            let ptr = item.as_ptr() as *const DataT;
                            let data = unsafe { std::ptr::read_unaligned(ptr) };

                            println!("Hit UProbe! PID: {}, PC: {:#x}", data.pid, data.pc);
                            target.last_context = Some(data);
                            event_received = true;
                        }

                        guard.clear_ready();

                        if event_received {
                            // 告诉 GDB：目标因为 TRAP (断点) 停下来了
                            return Ok(run_blocking::Event::TargetStopped(
                                SingleThreadStopReason::Signal(Signal::SIGTRAP)
                            ));
                        }
                    }
                }
            }
        })
    }

    fn on_interrupt(
        target: &mut Self::Target,
    ) -> Result<Option<Self::StopReason>, <Self::Target as Target>::Error> {
        use gdbstub::common::Signal;

        // 当 wait_for_stop_reason 返回 IncomingData(0x03) 后，gdbstub 会调用此函数
        log::debug!(
            "GDB sent interrupt (Ctrl-C), stopping target pid {}",
            target.pid
        );

        // 1. 向实际进程发送 SIGSTOP (你需要实现这个 helper)
        send_sigstop(target.pid);

        // 2. 返回 StopReason，告诉 GDB 我们是因为信号停下的
        Ok(Some(SingleThreadStopReason::Signal(Signal::SIGINT)))
    }
}
