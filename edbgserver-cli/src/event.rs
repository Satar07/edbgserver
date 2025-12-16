use edbgserver_common::DataT;
use gdbstub::{
    common::Signal,
    stub::{
        MultiThreadStopReason,
        run_blocking::{BlockingEventLoop, Event, WaitForStopReasonError},
    },
    target::Target,
};
use log::{debug, info};

use crate::{connection::TokioConnection, target::EdbgTarget, utils::send_sigstop};
use tokio::{io::AsyncReadExt, runtime::Handle};

pub struct EdbgEventLoop {}

impl BlockingEventLoop for EdbgEventLoop {
    type Target = EdbgTarget;
    type Connection = TokioConnection;
    type StopReason = MultiThreadStopReason<u64>;

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
                        let mut pending_events = Vec::new();
                        while let Some(item) = target.ring_buf.next() {
                            let ptr = item.as_ptr() as *const DataT;
                            let data = unsafe { std::ptr::read_unaligned(ptr) };
                            pending_events.push(data);
                        }
                        guard.clear_ready();
                        if pending_events.is_empty() {
                            continue;
                        }
                        // uprobe is preferred to prevent perf event in 'uprobe single step area'
                        let best_event = pending_events.iter()
                            .find(|e| e.event_source == edbgserver_common::EdbgSource::Uprobe)
                            .or_else(|| pending_events.last());
                        if let Some(data) = best_event {
                            info!("Event! PID: {}, TID: {}, PC: {:#x}", data.pid, data.tid, data.pc);
                            target.context = Some(*data);
                            let stop_reason = target.determine_stop_reason(data.tid, data.pc, data.fault_addr);
                            target.handle_trap();
                            return Ok(Event::TargetStopped(stop_reason));
                        } else {
                            log::warn!("Received events but all were kernel-space traps. Ignoring.");
                            for e in pending_events {
                                log::debug!("Ignored artifact: PC={:#x}", e.pc);
                            }
                        }
                    }
                }
            }
        })
    }

    fn on_interrupt(
        target: &mut Self::Target,
    ) -> Result<Option<Self::StopReason>, <Self::Target as Target>::Error> {
        debug!(
            "GDB sent interrupt (Ctrl-C), stopping target pid {}",
            target.get_pid()?
        );
        send_sigstop(target.get_pid()?);
        Ok(Some(MultiThreadStopReason::Signal(Signal::SIGINT)))
    }
}
