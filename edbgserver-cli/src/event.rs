use std::{io, os::fd::AsFd};

use edbgserver_common::DataT;
use gdbstub::{
    common::Signal,
    conn::ConnectionExt,
    stub::{
        MultiThreadStopReason,
        run_blocking::{BlockingEventLoop, Event, WaitForStopReasonError},
    },
    target::Target,
};
use log::{debug, info, warn};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

use crate::{connection::BufferedConnection, target::EdbgTarget, utils::send_sig_to_process};

pub struct EdbgEventLoop {}

type StopError = WaitForStopReasonError<<EdbgTarget as Target>::Error, std::io::Error>;
type StopEvent = Event<MultiThreadStopReason<u64>>;

impl EdbgEventLoop {
    /// Polls both the connection and the target file descriptors.
    /// Returns a tuple of booleans: (connection_readable, target_readable).
    fn poll_resources(
        conn: &mut BufferedConnection,
        target: &EdbgTarget,
    ) -> Result<(bool, bool), StopError> {
        let conn_fd = conn.as_fd();
        let target_fd = target.notifier.as_fd();

        let mut fds = [
            PollFd::new(conn_fd, PollFlags::POLLIN),
            PollFd::new(target_fd, PollFlags::POLLIN),
        ];

        if let Err(e) = poll(&mut fds, PollTimeout::NONE) {
            if e == nix::errno::Errno::EINTR {
                return Ok((false, false));
            }
            return Err(WaitForStopReasonError::Connection(io::Error::from(e)));
        }

        let conn_revents = fds[0].revents();
        let target_revents = fds[1].revents();

        Ok((
            conn_revents.is_some_and(|r| r.contains(PollFlags::POLLIN)),
            target_revents.is_some_and(|r| r.contains(PollFlags::POLLIN)),
        ))
    }

    /// Checks if there is incoming data from GDB.
    fn check_connection(conn: &mut BufferedConnection) -> Result<Option<StopEvent>, StopError> {
        match conn.peek() {
            Ok(Some(byte)) => Ok(Some(Event::IncomingData(byte))),
            Ok(None) => Ok(None),
            Err(e) => Err(WaitForStopReasonError::Connection(e)),
        }
    }

    /// Consumes events from the ring buffer, applies PID/TID filtering logic,
    /// and returns a list of valid pending events.
    fn collect_valid_events(target: &mut EdbgTarget) -> Vec<DataT> {
        let mut pending_events = Vec::new();

        debug!(
            "bound tid: {:?}, bound pid: {:?}",
            target.bound_tid, target.bound_pid
        );

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

            debug!(
                "Received event: PID={}, TID={}, PC={:#x}, FA={:#x}, SRC={:?}",
                data.pid,
                data.tid,
                data.pc(),
                data.fault_addr,
                data.event_source
            );

            if let Some(b_tid) = target.bound_tid
                && !target.is_multi_thread
                && data.tid != b_tid
            {
                continue;
            }

            // don't check the pid
            pending_events.push(DataT {
                pid: target.bound_pid.unwrap(),
                ..data
            });
        }

        pending_events
    }

    /// Selects the best event from pending events (prioritizing Uprobes),
    /// updates the target context, and returns the StopEvent.
    fn resolve_stop_event(
        target: &mut EdbgTarget,
        pending_events: Vec<DataT>,
    ) -> Result<Option<StopEvent>, StopError> {
        if pending_events.is_empty() {
            return Ok(None);
        }

        // uprobe is preferred to prevent perf event in 'uprobe single step area'
        let best_event = pending_events
            .iter()
            .find(|e| e.event_source == edbgserver_common::EdbgSource::Uprobe)
            .or_else(|| pending_events.last());

        if let Some(data) = best_event {
            info!(
                "Event! PID: {}, TID: {}, PC: {:#x}",
                data.pid,
                data.tid,
                data.pc()
            );

            target.context = Some(*data);
            let stop_reason = target.determine_stop_reason(data.tid, data.pc(), data.fault_addr);

            target
                .handle_trap()
                .map_err(WaitForStopReasonError::Target)?;

            Ok(Some(Event::TargetStopped(stop_reason)))
        } else {
            warn!("Received events but all were kernel-space traps. Ignoring.");
            for e in pending_events {
                debug!("Ignored artifact: PC={:#x}", e.pc());
            }
            Ok(None)
        }
    }

    /// Handles the entire flow when the target fd is readable.
    fn handle_target_activity(target: &mut EdbgTarget) -> Result<Option<StopEvent>, StopError> {
        let pending_events = Self::collect_valid_events(target);

        if pending_events.is_empty() {
            // however, the target has been stopped. so we must continue it again
            if let Some(pid) = target.bound_pid {
                send_sig_to_process(pid, &Signal::SIGCONT);
            }
            return Ok(None);
        }

        Self::resolve_stop_event(target, pending_events)
    }
}

impl BlockingEventLoop for EdbgEventLoop {
    type Connection = BufferedConnection;
    type StopReason = MultiThreadStopReason<u64>;
    type Target = EdbgTarget;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> Result<
        Event<Self::StopReason>,
        WaitForStopReasonError<<Self::Target as Target>::Error, std::io::Error>,
    > {
        info!("Waiting for target to stop...");

        loop {
            if conn.has_buffered_data()
                && let Some(event) = Self::check_connection(conn)?
            {
                return Ok(event);
            }
            let (conn_ready, target_ready) = Self::poll_resources(conn, target)?;

            // Handle Connection Activity
            if conn_ready && let Some(event) = Self::check_connection(conn)? {
                return Ok(event);
            }

            // Handle Target Activity
            if target_ready && let Some(event) = Self::handle_target_activity(target)? {
                return Ok(event);
            }
        }
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
