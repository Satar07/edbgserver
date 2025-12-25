use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
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

impl SwBreakpoint for EdbgTarget {
    fn add_sw_breakpoint(
        &mut self,
        addr: u64,
        _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        if self.active_sw_breakpoints.contains_key(&addr) {
            return Ok(false);
        }
        self.internel_attach_uprobe(addr)
            .map_err(|e| {
                error!("Failed to attach UProbe at VMA {:#x}: {}", addr, e);
                TargetError::NonFatal
            })
            .map(|link_id| {
                info!("Attached UProbe at VMA: {:#x}", addr);
                self.active_sw_breakpoints.insert(addr, link_id);
                true
            })
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: u64,
        _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        if let Some(link_id) = self.active_sw_breakpoints.remove(&addr) {
            log::info!("Detaching UProbe at VMA: {:#x}", addr);
            self.get_probe_program().detach(link_id).map_err(|e| {
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
        if self.active_hw_breakpoints.contains_key(&addr) {
            return Ok(false);
        }
        match self.internel_attach_perf_event_break_point(addr) {
            Ok(link_id) => {
                info!("Attached perf event at VMA: {:#x}", addr);
                self.active_hw_breakpoints.insert(addr, link_id);
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
        if let Some(link_id) = self.active_hw_breakpoints.remove(&addr) {
            log::info!("Detaching perf event at VMA: {:#x}", addr);
            self.get_perf_event_program().detach(link_id).map_err(|e| {
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
    link_id: PerfEventLinkId,
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
        if self.active_hw_watchpoint.contains_key(&addr) {
            return Ok(false);
        }
        match self.internel_attach_perf_event_watch_point(addr, len, kind) {
            Ok(link_id) => {
                info!("Attached perf event (watch point) at VMA: {:#x}", addr);
                self.active_hw_watchpoint
                    .insert(addr, WatchPointMeta { link_id, kind, len });
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
        if let Some(watch_point_meta) = self.active_hw_watchpoint.remove(&addr) {
            log::info!("Detaching perf event (watch point) at VMA: {:#x}", addr);
            self.get_perf_event_program()
                .detach(watch_point_meta.link_id)
                .map_err(|e| {
                    error!("aya detach failed: {}", e);
                    TargetError::NonFatal
                })?;
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
                error!("Cannot attach uprobe to anonymous memory at {:#x}", vma);
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
                    "aya uprobe attach failed. location: {:#x}, target: {:?}, pid: {}. error: {}",
                    location, target, target_pid, e
                );
                anyhow::anyhow!("aya urpobe attach failed: {}", e)
            })?;
        Ok(link_id)
    }

    pub fn internel_attach_perf_event_break_point(&mut self, addr: u64) -> Result<PerfEventLinkId> {
        debug!("Attaching perf event to {}", addr);
        let config = PerfEventConfig::Breakpoint(BreakpointConfig::Instruction { address: addr });
        let scope = PerfEventScope::OneProcess {
            pid: self.get_pid()?,
            cpu: None,
        };
        let sample_policy = SamplePolicy::Period(1); // sample every events
        let link_id = self
            .get_perf_event_program()
            .attach(config, scope, sample_policy, true)
            .map_err(|e| {
                error!(
                    "aya perf event attach failed. addr: {:#x}, pid: {}. error: {}",
                    addr,
                    self.get_pid().unwrap_or(0),
                    e
                );
                anyhow::anyhow!("aya perf event attach failed: {}", e)
            })?;
        Ok(link_id)
    }

    pub fn internel_attach_perf_event_watch_point(
        &mut self,
        address: u64,
        length: u64,
        kind: WatchKind,
    ) -> Result<PerfEventLinkId> {
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
        let scope = PerfEventScope::OneProcess {
            pid: self.get_pid()?,
            cpu: None,
        };
        let sample_policy = SamplePolicy::Period(1); // sample every events
        debug!("attach args: {:?} {:?} {:?}", config, scope, sample_policy);
        let link_id = self
            .get_perf_event_program()
            .attach(config, scope, sample_policy, true)
            .map_err(|e| anyhow::anyhow!("aya attach failed: {}", e))?;
        Ok(link_id)
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

        self.init_probe_link_id = Some(link_id);
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
            let target_pid = first_event.pid;
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
            if !self.is_multi_thread {
                self.thread_filter
                    .set(0, ThreadFilter::Some(target_tid), 0)
                    .context(anyhow!("thread filter set failed"))?;
            }

            if let Some(link_id) = self.init_probe_link_id.take() {
                info!("Removing initial temporary breakpoint");
                if let Err(e) = self.get_probe_program().detach(link_id) {
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
        if self.active_sw_breakpoints.contains_key(&pc) {
            debug!("Software breakpoint hit at {:#x} for TID: {}", pc, tid);
            return MultiThreadStopReason::SwBreak(tid);
        }
        if self.active_hw_breakpoints.contains_key(&pc) {
            debug!("Hardware breakpoint hit at {:#x} for TID: {}", pc, tid);
            return MultiThreadStopReason::HwBreak(tid);
        }
        for (watch_start, meta) in &self.active_hw_watchpoint {
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

        debug!("stop reason fallback to SIGSTOP for TID: {}", tid);
        MultiThreadStopReason::SignalWithThread {
            tid,
            signal: gdbstub::common::Signal::SIGSTOP,
        }
    }

    pub fn handle_trap(&mut self) {
        if let Some(context) = &self.context {
            debug!(
                "Handling trap for PID: {}, PC: {:#x}",
                context.tid,
                context.pc()
            );
            if let Some((addr, link_id)) = self.temp_step_breakpoints.take() {
                if addr == context.pc() {
                    debug!(
                        "Temp breakpoint hit at {:#x} for PID: {}. Detaching UProbe.",
                        addr, context.tid
                    );
                    if let Err(e) = self.get_probe_program().detach(link_id) {
                        error!("Failed to detach UProbe at {:#x}: {}", addr, e);
                    }
                } else {
                    debug!(
                        "Trap at {:#x} does not match temp breakpoint at {:#x}. Cleaning up temp BP anyway.",
                        context.pc(),
                        addr
                    );
                    let _ = self.get_probe_program().detach(link_id);
                }
            }
        } else {
            error!("No context available to handle trap.");
        }
    }
}
