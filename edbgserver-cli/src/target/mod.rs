use std::os::fd::OwnedFd;
use std::{collections::HashMap, path::PathBuf};

use anyhow::Result;
use aya::{
    Ebpf,
    maps::{MapData, RingBuf},
    programs::{UProbe, uprobe::UProbeLinkId},
};
use edbgserver_common::DataT;
use gdbstub::{
    common::Tid,
    target::{
        Target, TargetError, TargetResult,
        ext::{
            base::{
                BaseOps,
                multithread::{MultiThreadBase, MultiThreadResumeOps},
            },
            breakpoints::BreakpointsOps,
        },
    },
};
use gdbstub_arch::aarch64::{AArch64, reg::AArch64CoreRegs};
use log::{debug, warn};
use std::os::fd::AsFd;
use tokio::io::{Interest, unix::AsyncFd};

use crate::target::multithread::ThreadAction;

mod breakpoint;
mod memory_map;
mod multithread;
mod step;

pub struct EdbgTarget {
    ebpf: Ebpf,
    pub context: Option<DataT>,
    pub ring_buf: RingBuf<MapData>,
    pub notifier: AsyncFd<OwnedFd>,
    active_breakpoints: HashMap<u64, UProbeLinkId>,
    temp_step_breakpoints: Option<(u64, UProbeLinkId)>,
    resume_actions: Vec<(Tid, ThreadAction)>,
    exec_path: Option<PathBuf>,
    bound_pid: Option<u32>,
}

impl EdbgTarget {
    pub fn new(mut ebpf: Ebpf) -> Self {
        let program: &mut UProbe = ebpf
            .program_mut("edbgserver")
            .expect("cannot find ebpf program edbgserver")
            .try_into()
            .expect("failed to convert ebpf program to uProbe");
        program.load().expect("failed to load uProbe program");
        let event_map = ebpf.take_map("EVENTS").expect("EVENTS map not found");
        let ringbuf = RingBuf::try_from(event_map).expect("failed to convert map to ringbuf");
        let notifier = AsyncFd::with_interest(
            ringbuf
                .as_fd()
                .try_clone_to_owned()
                .expect("failed to clone ringbuf fd"),
            Interest::READABLE,
        )
        .expect("failed to create AsyncFd for ringbuf");
        Self {
            ebpf,
            context: None,
            ring_buf: ringbuf,
            notifier,
            active_breakpoints: HashMap::new(),
            temp_step_breakpoints: None,
            resume_actions: Vec::new(),
            exec_path: None,
            bound_pid: None,
        }
    }

    fn program_mut(&mut self) -> &mut UProbe {
        self.ebpf
            .program_mut("edbgserver")
            .expect("cannot find ebpf program edbgserver")
            .try_into()
            .expect("failed to convert ebpf program to uProbe")
    }

    pub fn get_pid(&self) -> Result<u32> {
        self.bound_pid
            .ok_or_else(|| anyhow::anyhow!("Target process is not running or not attached"))
    }
}

impl Target for EdbgTarget {
    type Arch = AArch64;

    type Error = anyhow::Error;

    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::MultiThread(self)
    }

    #[inline(always)]
    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_memory_map(
        &mut self,
    ) -> Option<gdbstub::target::ext::memory_map::MemoryMapOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_extended_mode(
        &mut self,
    ) -> Option<gdbstub::target::ext::extended_mode::ExtendedModeOps<'_, Self>> {
        Some(self)
    }
}

impl MultiThreadBase for EdbgTarget {
    fn read_registers(
        &mut self,
        regs: &mut AArch64CoreRegs,
        tid: gdbstub::common::Tid,
    ) -> TargetResult<(), Self> {
        if let Some(ctx) = &self.context {
            if ctx.tid == tid.get() as u32 {
                regs.x = ctx.regs;
                regs.pc = ctx.pc;
                regs.sp = ctx.sp;
                regs.cpsr = ctx.pstate as u32;
                return Ok(());
            } else {
                debug!("Req regs for TID {} but context is for {}", tid, ctx.tid);
            }
        }
        warn!(
            "Requesting registers for TID {} but no matching context",
            tid
        );
        debug!("last_context: {:?}", self.context);
        Ok(())
    }

    fn write_registers(
        &mut self,
        _regs: &<Self::Arch as gdbstub::arch::Arch>::Registers,
        _tid: gdbstub::common::Tid,
    ) -> TargetResult<(), Self> {
        warn!("write_registers not fully implemented (requires ptrace or inline hooking)");
        Ok(())
    }

    fn read_addrs(
        &mut self,
        start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        data: &mut [u8],
        tid: gdbstub::common::Tid,
    ) -> TargetResult<usize, Self> {
        use process_memory::{CopyAddress, TryIntoProcessHandle};
        let handle = (tid.get() as i32).try_into_process_handle().map_err(|e| {
            warn!("Failed to create process handle: {}", e);
            TargetError::Io(e)
        })?;
        match handle.copy_address(start_addr as usize, data) {
            Ok(_) => Ok(data.len()),
            Err(e) => {
                debug!("Failed to read memory at {:#x}: {}", start_addr, e); // that usual happends
                Err(TargetError::Io(e))
            }
        }
    }

    fn write_addrs(
        &mut self,
        start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        data: &[u8],
        tid: gdbstub::common::Tid,
    ) -> TargetResult<(), Self> {
        use process_memory::{PutAddress, TryIntoProcessHandle};
        let handle = (tid.get() as i32).try_into_process_handle().map_err(|e| {
            warn!("Failed to create process handle: {}", e);
            TargetError::Io(e)
        })?;
        match handle.put_address(start_addr as usize, data) {
            Ok(_) => Ok(()),
            Err(e) => {
                warn!("Failed to write memory at {:x}: {}", start_addr, e);
                Err(TargetError::Io(e))
            }
        }
    }

    fn list_active_threads(
        &mut self,
        thread_is_active: &mut dyn FnMut(gdbstub::common::Tid),
    ) -> Result<(), Self::Error> {
        debug!("listing active threads");
        let threads = self.get_active_threads()?;
        for tid in threads {
            thread_is_active(tid);
        }
        Ok(())
    }

    #[inline(always)]
    fn support_resume(&mut self) -> Option<MultiThreadResumeOps<'_, Self>> {
        Some(self)
    }
}
