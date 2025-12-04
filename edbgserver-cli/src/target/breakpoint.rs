use std::{path::PathBuf, str::FromStr};

use anyhow::Result;
use gdbstub::target::{
    TargetError, TargetResult,
    ext::breakpoints::{Breakpoints, SwBreakpoint, SwBreakpointOps},
};
use log::{error, info};
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
        let (location, target) = self.resolve_vma_to_probe_location(addr).map_err(|_| {
            error!(
                "Failed to resolve VMA to probe location for addr {:#x}",
                addr
            );
            TargetError::NonFatal
        })?;

        log::info!(
            "Attaching UProbe to {:?} at offset {:#x} (VMA: {:#x})",
            target,
            location,
            addr
        );
        let target_pid = self.get_pid().map_err(|_| TargetError::NonFatal)?;
        let link_id = self
            .program_mut()
            .attach(location, target.canonicalize()?, Some(target_pid), None)
            .map_err(|e| {
                error!("aya attach failed: {}", e);
                TargetError::NonFatal
            })?;

        self.active_breakpoints.insert(addr, link_id);
        Ok(true)
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

    pub fn attach_init_probe(&mut self, break_point: u64, target_pid: Option<u32>) -> Result<()> {
        info!("Attaching Initial UProbe at {} (Global)", break_point);
        let binary_target = PathBuf::from_str(&self.binary)?;
        let link_id = self.program_mut().attach(
            break_point,
            binary_target.canonicalize()?,
            target_pid,
            None,
        )?;

        self.active_breakpoints.insert(break_point, link_id);
        Ok(())
    }
}
