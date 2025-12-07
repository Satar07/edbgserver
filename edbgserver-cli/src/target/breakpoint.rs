use std::{path::PathBuf, str::FromStr};

use anyhow::Result;
use aya::programs::uprobe::UProbeLinkId;
use edbgserver_common::DataT;
use gdbstub::target::{
    TargetError, TargetResult,
    ext::breakpoints::{Breakpoints, SwBreakpoint, SwBreakpointOps},
};
use log::{debug, error, info};
use procfs::process::MMapPath;

use crate::target::EdbgTarget;

impl Breakpoints for EdbgTarget {
    #[inline(always)]
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }
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
                self.active_breakpoints.insert(addr, link_id);
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
            self.program_mut().detach(link_id).map_err(|e| {
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
            .program_mut()
            .attach(location, target.canonicalize()?, Some(target_pid), None)
            .map_err(|e| anyhow::anyhow!("aya attach failed: {}", e))?;
        Ok(link_id)
    }

    pub fn attach_init_probe(
        &mut self,
        binary: &str,
        break_point: u64,
        target_pid: Option<u32>,
    ) -> Result<()> {
        let binary_target = PathBuf::from_str(binary)?;
        info!(
            "Attaching Initial UProbe at {}:{}",
            binary_target.canonicalize()?.as_os_str().display(),
            break_point
        );
        let link_id = self.program_mut().attach(
            break_point,
            binary_target.canonicalize()?,
            target_pid,
            None,
        )?;

        self.active_breakpoints.insert(break_point, link_id);
        Ok(())
    }

    pub async fn wait_for_init_trap(&mut self) -> Result<()> {
        info!("Waiting for target process to hit the initial breakpoint...");

        loop {
            let mut guard = self.notifier.readable_mut().await?;
            if let Some(item) = self.ring_buf.next() {
                let ptr = item.as_ptr() as *const DataT;
                let data = unsafe { std::ptr::read_unaligned(ptr) };
                info!("Initial UProbe Hit! PID: {}, PC: {:#x}", data.tid, data.pc);
                self.context = Some(data);
                guard.clear_ready();
                return Ok(());
            }
            guard.clear_ready();
        }
    }

    pub fn handle_trap(&mut self) {
        if let Some(context) = &self.context {
            debug!(
                "Handling trap for PID: {}, PC: {:#x}",
                context.tid, context.pc
            );
            if let Some((addr, link_id)) = self.temp_step_breakpoints.take() {
                if addr == context.pc {
                    debug!(
                        "Temp breakpoint hit at {:#x} for PID: {}. Detaching UProbe.",
                        addr, context.tid
                    );
                    if let Err(e) = self.program_mut().detach(link_id) {
                        error!("Failed to detach UProbe at {:#x}: {}", addr, e);
                    }
                } else {
                    debug!(
                        "Trap at {:#x} does not match temp breakpoint at {:#x}. Cleaning up temp BP anyway.",
                        context.pc, addr
                    );
                    let _ = self.program_mut().detach(link_id);
                }
            }
        } else {
            error!("No context available to handle trap.");
        }
    }
}
