use std::path::PathBuf;

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
use log::{debug, error, info, warn};
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
        if self.active_breakpoints.contains_key(&addr) {
            return Ok(false);
        }
        self.internel_attach_uprobe(addr)
            .map_err(|e| {
                error!("Failed to attach UProbe at VMA {:#x}: {}", addr, e);
                TargetError::NonFatal
            })
            .map(|link_id| {
                info!("Attached UProbe at VMA: {:#x}", addr);
                self.active_breakpoints
                    .insert(addr, BreakpointHandle::UProbe(link_id));
                true
            })
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: u64,
        _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        if let Some(link_id) = self.active_breakpoints.remove(&addr) {
            log::info!("Detaching UProbe at VMA: {:#x}", addr);
            self.detach_breakpoint_handle(link_id).map_err(|e| {
                error!("aya detach failed: {}", e);
                TargetError::NonFatal
            })?;
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
        if self.active_breakpoints.contains_key(&addr) {
            return Ok(false);
        }
        match self.internel_attach_perf_event_break_point(addr) {
            Ok(link_ids) => {
                info!("Attached perf event at VMA: {:#x}", addr);
                self.active_breakpoints
                    .insert(addr, BreakpointHandle::Perf(link_ids));
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
        if let Some(link_ids) = self.active_breakpoints.remove(&addr) {
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
        if let Some(watch_point_meta) = self.active_watchpoint.remove(&addr) {
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
                return Err(TargetError::NonFatal);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl EdbgTarget {
    fn resolve_vma_to_probe_location(&self, vma: u64) -> TargetResult<(u64, PathBuf), Self> {
        let pid = self.get_pid().map_err(|_| TargetError::NonFatal)?;
        let process =
            procfs::process::Process::new(pid as i32).expect("Failed to open process info");
        let maps = process.maps().expect("Failed to read process maps");

        for map in maps {
            if vma <= map.address.0 || vma > map.address.1 {
                continue;
            }
            if let MMapPath::Path(path) = map.pathname {
                let file_offset = vma - map.address.0 + map.offset;
                return Ok((file_offset, path));
            } else {
                error!(
                    "Cannot attach uprobe to anonymous memory at {:#x} (path name: {:?})",
                    vma, map.pathname
                );
                return Err(TargetError::NonFatal);
            }
        }
        error!("Failed to find mapping for VMA {:#x}", vma);
        Err(TargetError::NonFatal)
    }

    pub fn internel_attach_uprobe(&mut self, addr: u64) -> Result<UProbeLinkId> {
        let (location, target) = self.resolve_vma_to_probe_location(addr).map_err(|_| {
            anyhow::anyhow!(
                "Failed to resolve VMA to probe location for addr {:#x}",
                addr
            )
        })?;
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
        Ok(link_id)
    }

    pub fn internel_attach_perf_event_break_point(
        &mut self,
        addr: u64,
    ) -> Result<Vec<PerfEventLinkId>> {
        let pid = self.get_pid()?;
        debug!("Attaching perf event to {:#x} for process {}", addr, pid);
        let config = PerfEventConfig::Breakpoint(BreakpointConfig::Instruction { address: addr });
        let sample_policy = SamplePolicy::Period(1);
        let tasks = procfs::process::Process::new(pid as i32)
            .map_err(|e| anyhow::anyhow!("Failed to open process {}: {}", pid, e))?
            .tasks()
            .map_err(|e| anyhow::anyhow!("Failed to read tasks for pid {}: {}", pid, e))?;
        let mut links = Vec::new();
        let prog = self.get_perf_event_program();
        for task in tasks {
            let tid = match task {
                Ok(t) => t.tid,
                Err(e) => {
                    warn!("Skipping unreadable task for pid {}: {}", pid, e);
                    continue;
                }
            };
            let scope = PerfEventScope::OneProcess {
                pid: tid as u32,
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
            debug!("Attached perf event to thread TID: {}", tid);
            links.push(link_id);
        }
        Ok(links)
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
        let tasks = procfs::process::Process::new(pid as i32)
            .map_err(|e| anyhow::anyhow!("Failed to open process {}: {}", pid, e))?
            .tasks()
            .map_err(|e| anyhow::anyhow!("Failed to read tasks for pid {}: {}", pid, e))?;
        let mut links = Vec::new();
        let prog = self.get_perf_event_program();
        let sample_policy = SamplePolicy::Period(1); // sample every events
        for task in tasks {
            let tid = match task {
                Ok(t) => t.tid,
                Err(e) => {
                    warn!("Skipping unreadable task for pid {}: {}", pid, e);
                    continue;
                }
            };
            let scope = PerfEventScope::OneProcess {
                pid: tid as u32,
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
            "Attaching Initial UProbe at {}:{}",
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

        loop {
            let mut guard = self.notifier.readable_mut().await?;
            let mut captured_events = Vec::new();
            while let Some(item) = self.ring_buf.next() {
                let ptr = item.as_ptr() as *const DataT;
                let data = unsafe { std::ptr::read_unaligned(ptr) };
                captured_events.push(data);
            }
            guard.clear_ready();
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
        if let Some(breakpoint) = self.active_breakpoints.get(&pc) {
            match breakpoint {
                BreakpointHandle::UProbe(_uprobe_link_id) => {
                    debug!("Software breakpoint hit at {:#x} for TID: {}", pc, tid);
                    return MultiThreadStopReason::SwBreak(tid);
                }
                BreakpointHandle::Perf(_perf_event_link_ids) => {
                    debug!("Hardware breakpoint hit at {:#x} for TID: {}", pc, tid);
                    return MultiThreadStopReason::HwBreak(tid);
                }
            }
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
