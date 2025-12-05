use edbgserver_common::DataT;
use gdbstub::{
    common::Signal,
    stub::{
        SingleThreadStopReason,
        run_blocking::{BlockingEventLoop, Event, WaitForStopReasonError},
    },
    target::Target,
};
use log::info;

use crate::{connection::TokioConnection, target::EdbgTarget, utils::send_sigstop};
use tokio::{io::AsyncReadExt, runtime::Handle};

pub struct EdbgEventLoop {}

impl BlockingEventLoop for EdbgEventLoop {
    type Target = EdbgTarget;
    type Connection = TokioConnection;
    type StopReason = SingleThreadStopReason<u64>;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> Result<
        Event<Self::StopReason>,
        WaitForStopReasonError<<Self::Target as Target>::Error, std::io::Error>,
    > {
        info!("Waiting for target to stop...");
        Handle::current().block_on(async {
            loop {
                tokio::select! {
                    biased;
                    res = conn.stream.read_u8() => {
                        match res {
                            Ok(byte) => return Ok(Event::IncomingData(byte)),
                            Err(e) => return Err(WaitForStopReasonError::Connection(e)),
                        }
                    }

                    guard_res = target.notifier.readable() => {
                        let mut guard = match guard_res {
                            Ok(g) => g,
                            Err(e) => return Err(WaitForStopReasonError::Connection(e)),
                        };
                        let mut event_received = false;
                        while let Some(item) = target.ring_buf.next() {
                            let ptr = item.as_ptr() as *const DataT;
                            let data = unsafe { std::ptr::read_unaligned(ptr) };
                            info!("Hit UProbe! PID: {}, PC: {:#x}", data.pid, data.pc);
                            target.context = Some(data);
                            event_received = true;
                        }
                        guard.clear_ready();
                        if event_received {
                            return Ok(Event::TargetStopped(
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
        log::debug!(
            "GDB sent interrupt (Ctrl-C), stopping target pid {}",
            target.get_pid()?
        );
        send_sigstop(target.get_pid()?);
        Ok(Some(SingleThreadStopReason::Signal(Signal::SIGINT)))
    }
}
