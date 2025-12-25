use std::{
    collections::HashMap,
    os::fd::{AsFd, OwnedFd},
    path::PathBuf,
};

use anyhow::Result;
use aya::{
    Ebpf,
    maps::{Array, MapData, RingBuf},
    programs::{PerfEvent, UProbe, perf_event::PerfEventLinkId, uprobe::UProbeLinkId},
};
use edbgserver_common::{DataT, ThreadFilter};
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
#[cfg(target_arch = "aarch64")]
use gdbstub_arch::aarch64::{AArch64, reg::AArch64CoreRegs};
#[cfg(target_arch = "x86_64")]
use gdbstub_arch::x86::{X86_64_SSE, reg::X86_64CoreRegs};
use log::{debug, trace, warn};
use tokio::io::{Interest, unix::AsyncFd};

use crate::target::multithread::ThreadAction;

mod arch;
mod auvx;
mod breakpoint;
mod execfile;
mod host_io;
mod memory_map;
mod multithread;

pub struct EdbgTarget {
    ebpf: Ebpf,
    pub context: Option<DataT>,
    pub ring_buf: RingBuf<MapData>,
    pub notifier: AsyncFd<OwnedFd>,
    thread_filter: Array<MapData, ThreadFilter>,
    active_sw_breakpoints: HashMap<u64, UProbeLinkId>,
    active_hw_breakpoints: HashMap<u64, PerfEventLinkId>,
    active_hw_watchpoint: HashMap<u64, breakpoint::WatchPointMeta>,
    temp_step_breakpoints: Option<(u64, UProbeLinkId)>,
    init_probe_link_id: Option<UProbeLinkId>,
    resume_actions: Vec<(Tid, ThreadAction)>,
    is_scheduler_lock: bool,
    exec_path: Option<PathBuf>,
    pub bound_pid: Option<u32>,
    pub bound_tid: Option<u32>,
    host_io_files: HashMap<u32, std::fs::File>,
    next_host_io_fd: u32,
    pub is_multi_thread: bool,
}

pub const HOST_IO_FD_START: u32 = 100;

impl EdbgTarget {
    pub fn new(mut ebpf: Ebpf, is_multi_thread: bool) -> Self {
        let program: &mut UProbe = ebpf
            .program_mut("probe_callback")
            .expect("cannot find ebpf program probe_callback")
            .try_into()
            .expect("failed to convert ebpf program to uProbe");
        program.load().expect("failed to load uProbe program");
        let program: &mut PerfEvent = ebpf
            .program_mut("perf_callback")
            .expect("cannot find ebpf program perf_callback")
            .try_into()
            .expect("failed to convert ebpf program to PerfEvent");
        program.load().expect("failed to load PerfEvent program");
        let event_map = ebpf.take_map("EVENTS").expect("EVENTS map not found");
        let ringbuf = RingBuf::try_from(event_map).expect("failed to convert map to ringbuf");
        let thread_filter = ebpf
            .take_map("THREAD_FILTER")
            .expect("THREAD_FILTER map not found");
        let thread_filter: Array<MapData, ThreadFilter> =
            Array::try_from(thread_filter).expect("failed to convert filter map");
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
            thread_filter,
            active_sw_breakpoints: HashMap::new(),
            active_hw_breakpoints: HashMap::new(),
            active_hw_watchpoint: HashMap::new(),
            temp_step_breakpoints: None,
            init_probe_link_id: None,
            resume_actions: Vec::new(),
            is_scheduler_lock: false,
            exec_path: None,
            bound_pid: None,
            bound_tid: None,
            host_io_files: HashMap::new(),
            next_host_io_fd: HOST_IO_FD_START,
            is_multi_thread,
        }
    }

    fn get_probe_program(&mut self) -> &mut UProbe {
        self.ebpf
            .program_mut("probe_callback")
            .expect("cannot find ebpf program probe_callback")
            .try_into()
            .expect("failed to convert ebpf program to uProbe")
    }

    fn get_perf_event_program(&mut self) -> &mut PerfEvent {
        self.ebpf
            .program_mut("perf_callback")
            .expect("cannot find ebpf program perf_callback")
            .try_into()
            .expect("failed to convert ebpf program to PerfEvent")
    }

    pub fn get_pid(&self) -> Result<u32> {
        self.bound_pid
            .ok_or_else(|| anyhow::anyhow!("Target process is not running or not attached"))
    }
}

impl Target for EdbgTarget {
    #[cfg(target_arch = "aarch64")]
    type Arch = AArch64;
    #[cfg(target_arch = "x86_64")]
    type Arch = X86_64_SSE;

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

    #[inline(always)]
    fn support_host_io(&mut self) -> Option<gdbstub::target::ext::host_io::HostIoOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_exec_file(
        &mut self,
    ) -> Option<gdbstub::target::ext::exec_file::ExecFileOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_auxv(&mut self) -> Option<gdbstub::target::ext::auxv::AuxvOps<'_, Self>> {
        Some(self)
    }
}

impl MultiThreadBase for EdbgTarget {
    #[cfg(target_arch = "aarch64")]
    fn read_registers(
        &mut self,
        regs: &mut AArch64CoreRegs,
        tid: gdbstub::common::Tid,
    ) -> TargetResult<(), Self> {
        if let Some(ctx) = &self.context {
            if !self.is_multi_thread || ctx.tid == tid.get() as u32 {
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

    #[cfg(target_arch = "x86_64")]
    fn read_registers(
        &mut self,
        regs: &mut X86_64CoreRegs,
        tid: gdbstub::common::Tid,
    ) -> TargetResult<(), Self> {
        if let Some(ctx) = &self.context {
            if !self.is_multi_thread || ctx.tid == tid.get() as u32 {
                regs.regs[0] = ctx.rax;
                regs.regs[1] = ctx.rbx;
                regs.regs[2] = ctx.rcx;
                regs.regs[3] = ctx.rdx;
                regs.regs[4] = ctx.rsi;
                regs.regs[5] = ctx.rdi;
                regs.regs[6] = ctx.rbp;
                regs.regs[7] = ctx.rsp;
                regs.regs[8] = ctx.r8;
                regs.regs[9] = ctx.r9;
                regs.regs[10] = ctx.r10;
                regs.regs[11] = ctx.r11;
                regs.regs[12] = ctx.r12;
                regs.regs[13] = ctx.r13;
                regs.regs[14] = ctx.r14;
                regs.regs[15] = ctx.r15;
                regs.rip = ctx.rip;
                regs.eflags = ctx.rflags as u32;
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
        trace!("listing active threads");
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
