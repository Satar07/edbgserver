use std::path::PathBuf;

use gdbstub::target::{
    TargetError, TargetResult,
    ext::breakpoints::{Breakpoints, SwBreakpoint, SwBreakpointOps},
};
use log::error;
use procfs::process::MMapPath;

use crate::target::EdbgTarget;

type BreakPointHandle = Box<aya::programs::uprobe::UProbeLink>;

impl Breakpoints for EdbgTarget {
    // 启用软件断点支持
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
    ) -> gdbstub::target::TargetResult<bool, Self> {
        // 1. 读取当前地址的一个字节（原始指令）
        let mut buf = [0u8; 1];
        self.mem.read(addr, &mut buf).map_err(TargetError::Io)?; // 假设你的 read 返回 io::Result
        let original_byte = buf[0];

        // 2. 将原始字节保存到 HashMap 中
        self.saved_breakpoints.insert(addr, original_byte);

        Ok(true) // 返回 true 表示支持并成功添加
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: u64,
        _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
    ) -> gdbstub::target::TargetResult<bool, Self> {
        // 1. 从 HashMap 中取出原始字节
        Ok(true)
    }
}

struct ProbeLocation {
    path: PathBuf,
    offset: u64,
}

impl EdbgTarget {
    fn resolve_vma_to_probe_location(&self, vma: u64) -> TargetResult<ProbeLocation, Self> {
        let process =
            procfs::process::Process::new(self.pid).expect("Failed to open process procfs entry");
        let maps = process.maps().expect("Failed to read process maps");

        for map in maps {
            if vma <= map.address.0 || vma > map.address.1 {
                continue;
            }
            if let MMapPath::Path(path) = map.pathname {
                let file_offset = vma - map.address.0 + map.offset;
                return Ok(ProbeLocation {
                    path,
                    offset: file_offset,
                });
            } else {
                error!("Cannot attach uprobe to anonymous memory at {:#x}", vma);
                return Err(TargetError::NonFatal);
            }
        }
        todo!()
    }
}
