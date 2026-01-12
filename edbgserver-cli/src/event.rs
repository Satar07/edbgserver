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
use tokio::{io::AsyncReadExt, runtime::Handle};

use crate::{connection::TokioConnection, target::EdbgTarget, utils::send_sig_to_process};

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
                        debug!("bound tid: {:?}, bound pid: {:?}", target.bound_tid, target.bound_pid);
                        // HACK: Handling PID/TID mismatch in Linux Namespaces (e.g., WSL, Docker).
                        //
                        // The PID/TID captured by eBPF are global IDs from the root namespace. However,
                        // when edbgserver runs inside a child namespace, these IDs are invalid for
                        // local operations. Since escaping the namespace to find the PID mapping is
                        // difficult, we use a heuristic approach:
                        //
                        // 1. PID Overriding: We assume the event belongs to our target process and
                        //    manually overwrite the event's PID with our locally known `bound_pid`.
                        // 2. TID Limitation: We cannot reliably map the global TID back to the local
                        //    namespace. Therefore, we prefer using PID-based operations (like memory
                        //    reading) whenever possible.
                        //
                        // Note: This creates a strict one-way flow. Local IDs can be sent to eBPF,
                        // but IDs received from eBPF must be treated as unreliable in this namespace.
                        while let Some(item) = target.ring_buf.next() {
                            let ptr = item.as_ptr() as *const DataT;
                            let data = unsafe { std::ptr::read_unaligned(ptr) };
                            debug!("Received event: PID={}, TID={}, PC={:#x}, FA={:#x}, SRC={:?}",
                                data.pid, data.tid, data.pc(), data.fault_addr, data.event_source);
                            if let Some(b_tid) = target.bound_tid
                                && !target.is_multi_thread
                                && data.tid != b_tid
                            {
                                continue;
                            }
                            // don't check the pid
                            pending_events.push(DataT{pid: target.bound_pid.unwrap(), ..data});
                        }
                        guard.clear_ready();
                        if pending_events.is_empty() {
                            // however, the target has been stopped. so we must continue it again
                            send_sig_to_process(target.bound_pid.unwrap(), &Signal::SIGCONT);
                            continue;
                        }
                        // uprobe is preferred to prevent perf event in 'uprobe single step area'
                        let best_event = pending_events.iter()
                            .find(|e| e.event_source == edbgserver_common::EdbgSource::Uprobe)
                            .or_else(|| pending_events.last());
                        if let Some(data) = best_event {
                            info!("Event! PID: {}, TID: {}, PC: {:#x}", data.pid, data.tid, data.pc());
                            target.context = Some(*data);
                            let stop_reason = target.determine_stop_reason(data.tid, data.pc(), data.fault_addr);
                            target.handle_trap().map_err(WaitForStopReasonError::Target)?;
                            return Ok(Event::TargetStopped(stop_reason));
                        } else {
                            log::warn!("Received events but all were kernel-space traps. Ignoring.");
                            for e in pending_events {
                                log::debug!("Ignored artifact: PC={:#x}", e.pc());
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
        send_sig_to_process(target.get_pid()?, &Signal::SIGSTOP);
        Ok(Some(MultiThreadStopReason::Signal(Signal::SIGSTOP)))
    }
}
