use std::{os::fd::AsFd, path::PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use aya::programs::{
    perf_event::{
        BreakpointConfig, PerfBreakpointLength, PerfBreakpointType, PerfEventConfig,
        PerfEventLinkId, PerfEventScope, SamplePolicy,
    },
    uprobe::UProbeLinkId,
};
use edbgserver_common::{DataT, ThreadFilter};
use gdbstub::{
    common::Tid,
    stub::MultiThreadStopReason,
    target::{
        TargetError, TargetResult,
        ext::breakpoints::{
            Breakpoints, HwBreakpoint, HwBreakpointOps, HwWatchpoint, HwWatchpointOps,
            SwBreakpoint, SwBreakpointOps, WatchKind,
        },
    },
};
use log::{debug, error, info, trace, warn};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use procfs::process::MMapPath;

use crate::target::EdbgTarget;

impl Breakpoints for EdbgTarget {
    #[inline(always)]
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_hw_watchpoint(&mut self) -> Option<HwWatchpointOps<'_, Self>> {
        Some(self)
    }
}

#[derive(Debug)]
pub enum BreakpointHandle {
    UProbe(UProbeLinkId),
    Perf(Vec<PerfEventLinkId>),
}

impl SwBreakpoint for EdbgTarget {
    fn add_sw_breakpoint(
        &mut self,
        addr: u64,
        _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        debug!("gdb ask add swbreakpoint for addr {:#x}", addr);
        if self.active_sw_breakpoints.contains_key(&addr) {
            return Ok(false);
        }
        match self.internel_attach_uprobe(addr) {
            Ok(link_id) => {
                info!("Attached UProbe at VMA: {:#x}", addr);
                self.active_sw_breakpoints.insert(addr, link_id);
                Ok(true)
            }
            Err(e) => {
                warn!(
                    "Failed to add SW breakpoint at {:#x}: {:#}, fallback to HW breakpoint...",
                    addr, e
                );
                match self.internel_attach_perf_event_break_point(addr) {
                    Ok(link_ids) => {
                        info!("Attached perf event at VMA: {:#x}", addr);
                        self.active_sw_breakpoints.insert(addr, link_ids);
                        Ok(true)
                    }
                    Err(e) => {
                        error!("Failed to attach perf event at VMA {:#x}: {}", addr, e);
                        Ok(false)
                    }
                }
            }
        }
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: u64,
        _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        debug!("gdb ask remove swbreakpoint for addr {:#x}", addr);
        if let Some(link_id) = self.active_sw_breakpoints.remove(&addr) {
            log::info!("Detaching UProbe at VMA: {:#x}", addr);
            if let Err(e) = self.detach_breakpoint_handle(link_id) {
                error!("Failed to detach SW breakpoint at {:#x}: {:#}", addr, e);
                return Ok(false);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl HwBreakpoint for EdbgTarget {
    fn add_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        debug!("gdb ask add hwbreakpoint for addr {:#x}", addr);
        if self.active_hw_breakpoints.contains_key(&addr) {
            return Ok(false);
        }
        match self.internel_attach_perf_event_break_point(addr) {
            Ok(link_ids) => {
                info!("Attached perf event at VMA: {:#x}", addr);
                self.active_hw_breakpoints.insert(addr, link_ids);
                Ok(true)
            }
            Err(e) => {
                error!("Failed to attach perf event at VMA {:#x}: {}", addr, e);
                Ok(false)
            }
        }
    }

    fn remove_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        debug!("gdb ask remove hwbreakpoint for addr {:#x}", addr);
        if let Some(link_ids) = self.active_hw_breakpoints.remove(&addr) {
            log::info!("Detaching perf events at VMA: {:#x}", addr);
            self.detach_breakpoint_handle(link_ids).map_err(|e| {
                error!("aya detach failed: {}", e);
                TargetError::NonFatal
            })?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub struct WatchPointMeta {
    link_ids: Vec<PerfEventLinkId>,
    kind: WatchKind,
    len: u64,
}

impl HwWatchpoint for EdbgTarget {
    fn add_hw_watchpoint(
        &mut self,
        addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        len: <Self::Arch as gdbstub::arch::Arch>::Usize,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        debug!(
            "gdb ask add hwwatchpoint for addr {:#x}, len {}, kind {:?}",
            addr, len, kind
        );
        if self.active_watchpoint.contains_key(&addr) {
            return Ok(false);
        }
        // x86 debug registers cannot trigger on read-only watchpoints, so the
        // kernel rejects `HW_BREAKPOINT_R` outright, see
        // https://github.com/torvalds/linux/blob/v6.12/arch/x86/kernel/hw_breakpoint.c#L345-L377.
        // so convert read to read/write here
        #[cfg(target_arch = "x86_64")]
        let kind = match kind {
            WatchKind::Read => {
                warn!(
                    "x86 architecture does not support read-only watchpoints. Converting to read/write watchpoint at {:#x}",
                    addr
                );
                WatchKind::ReadWrite
            }
            other => other,
        };

        match self.internel_attach_perf_event_watch_point(addr, len, kind) {
            Ok(link_ids) => {
                info!("Attached perf event (watch point) at VMA: {:#x}", addr);
                self.active_watchpoint.insert(
                    addr,
                    WatchPointMeta {
                        link_ids,
                        kind,
                        len,
                    },
                );
                Ok(true)
            }
            Err(e) => {
                error!("Failed to attach perf event at VMA {:#x}: {}", addr, e);
                Ok(false)
            }
        }
    }

    fn remove_hw_watchpoint(
        &mut self,
        addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        _len: <Self::Arch as gdbstub::arch::Arch>::Usize,
        _kind: gdbstub::target::ext::breakpoints::WatchKind,
    ) -> TargetResult<bool, Self> {
        debug!("gdb ask remove hwwatchpoint for addr {:#x}", addr);
        let Some(watch_point_meta) = self.active_watchpoint.remove(&addr) else {
            return Ok(false);
        };
        log::info!("Detaching perf event (watch point) at VMA: {:#x}", addr);
        let prog = self.get_perf_event_program();
        let all_success = watch_point_meta
            .link_ids
            .into_iter()
            .map(|id| {
                prog.detach(id)
                    .map_err(|e| {
                        error!("aya detach failed: {}", e);
                        e
                    })
                    .is_ok()
            })
            .collect::<Vec<_>>()
            .into_iter()
            .all(|ok| ok);
        if !all_success {
            error!(
                "One or more perf event detachments failed at VMA: {:#x}",
                addr
            );
            return Ok(false);
        }
        Ok(true)
    }
}

impl EdbgTarget {
    fn resolve_vma_to_probe_location(&self, vma: u64) -> Result<(u64, PathBuf)> {
        let pid = self.get_pid()?;
        let process =
            procfs::process::Process::new(pid as i32).expect("Failed to open process info");
        let maps = process.maps().expect("Failed to read process maps");

        for map in maps {
            if vma < map.address.0 || vma >= map.address.1 {
                continue;
            }
            if let MMapPath::Path(path) = map.pathname {
                let file_offset = vma - map.address.0 + map.offset;
                return Ok((file_offset, path));
            } else {
                bail!(
                    "Cannot attach uprobe to anonymous/special memory at {:#x} (name: {:?})",
                    vma,
                    map.pathname
                );
            }
        }
        bail!("Failed to find mapping for VMA {:#x}", vma);
    }

    pub fn internel_attach_uprobe(&mut self, addr: u64) -> Result<BreakpointHandle> {
        let (location, target) = self
            .resolve_vma_to_probe_location(addr)
            .context(format!("Failed to resolve VMA {:#x}", addr))?;
        let target_pid = self.get_pid()?;
        debug!(
            "Attaching Temp/Internal UProbe to {:?} at offset {:#x} (VMA: {:#x})",
            target, location, addr
        );
        let link_id = self
            .get_probe_program()
            .attach(location, target.canonicalize()?, Some(target_pid), None)
            .map_err(|e| {
                error!(
                    "aya uprobe attach failed. location: {:#x}, target: {:?}, pid: {}. error: {:#?}",
                    location, target, target_pid, e
                );
                anyhow::anyhow!("aya urpobe attach failed: {}", e)
            })?;
        Ok(BreakpointHandle::UProbe(link_id))
    }

    pub fn internel_attach_perf_event_break_point(
        &mut self,
        addr: u64,
    ) -> Result<BreakpointHandle> {
        let pid = self.get_pid()?;
        debug!("Attaching perf event to {:#x} for process {}", addr, pid);
        let config = PerfEventConfig::Breakpoint(BreakpointConfig::Instruction { address: addr });
        let sample_policy = SamplePolicy::Period(1);
        let tasks = if self.is_multi_thread {
            procfs::process::Process::new(pid as i32)
                .map_err(|e| anyhow::anyhow!("Failed to open process {}: {}", pid, e))?
                .tasks()?
                .filter_map(|t| t.ok())
                .map(|t| t.tid as u32)
                .collect::<Vec<_>>()
        } else {
            vec![self.bound_tid.expect("bound_tid is not set")]
        };
        let mut links = Vec::new();
        let prog = self.get_perf_event_program();
        for tid in tasks {
            let scope = PerfEventScope::OneProcess {
                pid: tid,
                cpu: None,
            };
            let link_id = prog
                .attach(config, scope, sample_policy, true)
                .map_err(|e| {
                    error!(
                        "aya perf event attach failed. addr: {:#x}, tid: {}. error: {:#?}",
                        addr, tid, e
                    );
                    anyhow::anyhow!("aya perf event attach failed for tid {}: {}", tid, e)
                })?;
            trace!("Attached perf event to thread TID: {}", tid);
            links.push(link_id);
        }
        Ok(BreakpointHandle::Perf(links))
    }

    pub fn internel_attach_perf_event_watch_point(
        &mut self,
        address: u64,
        length: u64,
        kind: WatchKind,
    ) -> Result<Vec<PerfEventLinkId>> {
        debug!("Attaching perf event (watch point) to {:#x}", address);
        let rw_flags = match kind {
            WatchKind::Write => PerfBreakpointType::Write,
            WatchKind::Read => PerfBreakpointType::Read,
            WatchKind::ReadWrite => PerfBreakpointType::ReadWrite,
        };
        let length = match length {
            1 => PerfBreakpointLength::Len1,
            2 => PerfBreakpointLength::Len2,
            4 => PerfBreakpointLength::Len4,
            8 => PerfBreakpointLength::Len8,
            _ => {
                return Err(anyhow::anyhow!(
                    "Unsupported watchpoint length: {}. Supported lengths are 1, 2, 4, or 8 bytes.",
                    length
                ));
            }
        };
        let config = PerfEventConfig::Breakpoint(BreakpointConfig::Data {
            r#type: rw_flags,
            address,
            length,
        });
        let pid = self.get_pid()?;
        let tasks = if self.is_multi_thread {
            procfs::process::Process::new(pid as i32)
                .map_err(|e| anyhow::anyhow!("Failed to open process {}: {}", pid, e))?
                .tasks()?
                .filter_map(|t| t.ok())
                .map(|t| t.tid as u32)
                .collect::<Vec<_>>()
        } else {
            vec![self.bound_tid.expect("bound_tid is not set")]
        };
        let mut links = Vec::new();
        let prog = self.get_perf_event_program();
        let sample_policy = SamplePolicy::Period(1); // sample every events
        for tid in tasks {
            let scope = PerfEventScope::OneProcess {
                pid: tid,
                cpu: None,
            };
            let link_id = prog
                .attach(config, scope, sample_policy, true)
                .map_err(|e| {
                    error!(
                        "aya perf event attach (watch point) failed. addr: {:#x}, tid: {}. error: {:#?}",
                        address, tid, e
                    );
                    anyhow::anyhow!("aya perf event attach (watch point) failed for tid {}: {}", tid, e)
                })?;
            debug!("Attached watch point to thread TID: {}", tid);
            links.push(link_id);
        }
        Ok(links)
    }

    fn detach_breakpoint_handle(&mut self, handle: BreakpointHandle) -> Result<()> {
        match handle {
            BreakpointHandle::UProbe(id) => self
                .get_probe_program()
                .detach(id)
                .map_err(|e| anyhow!("UProbe detach failed: {}", e)),
            BreakpointHandle::Perf(ids) => {
                let prog = self.get_perf_event_program();
                let mut last_err = None;
                for id in ids {
                    if let Err(e) = prog.detach(id) {
                        last_err = Some(e);
                    }
                }
                if let Some(e) = last_err {
                    bail!("Perf detach failed: {}", e);
                }
                Ok(())
            }
        }
    }

    pub fn attach_init_probe(
        &mut self,
        binary_target: PathBuf,
        break_point: u64,
        target_pid: Option<u32>,
    ) -> Result<()> {
        info!(
            "Attaching Initial UProbe at {}:{:#x}",
            binary_target.canonicalize()?.as_os_str().display(),
            break_point
        );
        let link_id = self.get_probe_program().attach(
            break_point,
            binary_target.canonicalize()?,
            target_pid,
            None,
        )?;
        self.bound_pid = target_pid;

        self.init_probe_link_id = Some(BreakpointHandle::UProbe(link_id));
        Ok(())
    }

    pub async fn wait_for_init_trap(&mut self) -> Result<()> {
        info!("Waiting for target process to hit the initial breakpoint...");
        let target_fd = self.notifier.as_fd();
        let mut fds = [PollFd::new(target_fd, PollFlags::POLLIN)];
        loop {
            poll(&mut fds, PollTimeout::NONE)?;
            let Some(revents) = fds[0].revents() else {
                continue;
            };
            if !revents.contains(PollFlags::POLLIN) {
                continue;
            }

            let mut captured_events = Vec::new();
            while let Some(item) = self.ring_buf.next() {
                let ptr = item.as_ptr() as *const DataT;
                let data = unsafe { std::ptr::read_unaligned(ptr) };
                captured_events.push(data);
            }
            if captured_events.is_empty() {
                continue;
            }

            // first event is the one we care about
            let first_event = captured_events.first().unwrap();
            // if the target pid is specify and doesn't match, this will happen in namespace scenario (e.g WSL)
            // we just map it to the our target pid
            let target_pid = if let Some(target_pid) = self.bound_pid
                && first_event.pid != target_pid
            {
                warn!(
                    "Mapped PID: {} to specified target PID: {} (this may happen in namespace scenarios like WSL)",
                    first_event.pid, target_pid
                );
                target_pid
            } else {
                first_event.pid
            };
            let target_tid = first_event.tid;
            let trap_pc = first_event.pc();

            info!(
                "Initial UProbe Hit! Locking onto PID: {}. TID: {}, PC: {:#x}",
                target_pid, target_tid, trap_pc
            );
            self.context = Some(*first_event);

            let exe = procfs::process::Process::new(target_pid as i32).and_then(|p| p.exe())?;
            debug!(
                "Target process executable path: {}",
                exe.canonicalize()?.as_os_str().display()
            );
            self.exec_path = Some(exe);
            self.bound_pid = Some(target_pid);
            self.bound_tid = Some(target_tid);

            use process_memory::TryIntoProcessHandle;
            self.process_memory_handle = (target_pid as i32).try_into_process_handle().ok();

            if let Err(e) = self.update_libraries_cache() {
                error!("Failed to update libraries cache in init trap: {}", e);
            }

            if !self.is_multi_thread {
                self.thread_filter
                    .set(0, ThreadFilter::Some(target_tid), 0)
                    .context(anyhow!("thread filter set failed"))?;
            }

            if let Some(link_id) = self.init_probe_link_id.take() {
                info!("Removing initial temporary breakpoint");
                if let Err(e) = self.detach_breakpoint_handle(link_id) {
                    error!("Failed to detach initial probe: {}", e);
                }
            } else {
                warn!(
                    "Initial trap hit at {:#x}, but no init urpobe link id to remove.",
                    trap_pc
                );
            }

            // handle any extra events from other processes in the same target
            for event in captured_events.iter().skip(1) {
                if event.pid != target_pid {
                    warn!(
                        "Ignored process PID: {} (PC: {:#x}). We are locked to PID: {}",
                        event.pid, trap_pc, target_pid
                    );
                } else {
                    debug!("Skipping extra event for target PID in init batch.");
                }
            }

            return Ok(());
        }
    }

    pub fn determine_stop_reason(
        &self,
        tid: u32,
        pc: u64,
        fault_addr: u64,
    ) -> MultiThreadStopReason<u64> {
        let tid = Tid::new(tid as usize).unwrap();
        if let Some((step_pc, _)) = self.temp_step_breakpoints
            && pc == step_pc
        {
            debug!("Step breakpoint hit at {:#x} for TID: {}", pc, tid);
            return MultiThreadStopReason::DoneStep;
        }
        if let Some(breakpoint) = self.active_sw_breakpoints.get(&pc) {
            match breakpoint {
                BreakpointHandle::UProbe(_uprobe_link_id) => {
                    debug!(
                        "Software UProbe breakpoint hit at {:#x} for TID: {}",
                        pc, tid
                    );
                    return MultiThreadStopReason::SwBreak(tid);
                }
                BreakpointHandle::Perf(_perf_event_link_ids) => {
                    debug!(
                        "Software perf event breakpoint hit at {:#x} for TID: {}",
                        pc, tid
                    );
                    return MultiThreadStopReason::SwBreak(tid);
                }
            }
        }
        if let Some(_breakpoint) = self.active_hw_breakpoints.get(&pc) {
            debug!("Hardware breakpoint hit at {:#x} for TID: {}", pc, tid);
            return MultiThreadStopReason::HwBreak(tid);
        }
        for (watch_start, meta) in &self.active_watchpoint {
            if fault_addr >= *watch_start && fault_addr < *watch_start + meta.len {
                debug!(
                    "Watchpoint hit at {:#x} (watch range: {:#x} - {:#x}) for TID: {}",
                    fault_addr,
                    watch_start,
                    watch_start + meta.len,
                    tid
                );
                return MultiThreadStopReason::Watch {
                    tid,
                    kind: meta.kind,
                    addr: *watch_start,
                };
            }
        }

        warn!("stop reason fallback to SIGSTOP for TID: {}", tid);
        MultiThreadStopReason::SignalWithThread {
            tid,
            signal: gdbstub::common::Signal::SIGSTOP,
        }
    }

    pub fn handle_trap(&mut self) -> Result<()> {
        let Some(context) = &self.context else {
            bail!("No context available to handle trap.");
        };
        debug!(
            "Handling trap for TID: {}, PC: {:#x}",
            context.tid,
            context.pc()
        );
        self.bound_tid = Some(context.tid);
        if let Some((addr, link_id)) = self.temp_step_breakpoints.take() {
            if addr == context.pc() {
                debug!(
                    "Temp breakpoint hit at {:#x} for TID: {}. Detaching UProbe.",
                    addr, context.tid
                );
                if let Err(e) = self.detach_breakpoint_handle(link_id) {
                    error!("Failed to detach UProbe at {:#x}: {}", addr, e);
                }
            } else {
                debug!(
                    "Trap at {:#x} does not match temp breakpoint at {:#x}. Cleaning up temp breakpoint anyway.",
                    context.pc(),
                    addr
                );
                let _ = self.detach_breakpoint_handle(link_id);
            }
        }
        self.update_libraries_cache()
    }
}
