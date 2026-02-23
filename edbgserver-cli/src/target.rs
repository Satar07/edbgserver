use std::{
    collections::HashMap,
    os::fd::{AsFd, OwnedFd},
    path::PathBuf,
};

use anyhow::{Result, anyhow};
use aya::{
    Ebpf,
    maps::{Array, MapData, RingBuf},
    programs::{PerfEvent, UProbe},
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
use log::{debug, error, trace, warn};

use crate::target::{arch::TargetArch, multithread::ThreadAction};

mod arch;
mod auvx;
mod breakpoint;
mod execfile;
mod host_io;
mod libraries;
mod memory_map;
mod multithread;

pub struct EdbgTarget {
    ebpf: Ebpf,
    pub context: Option<DataT>,
    pub ring_buf: RingBuf<MapData>,
    pub notifier: OwnedFd,
    thread_filter: Array<MapData, ThreadFilter>,
    active_sw_breakpoints: HashMap<u64, breakpoint::BreakpointHandle>,
    active_hw_breakpoints: HashMap<u64, breakpoint::BreakpointHandle>,
    active_watchpoint: HashMap<u64, breakpoint::WatchPointMeta>,
    temp_step_breakpoints: Option<(u64, breakpoint::BreakpointHandle)>,
    init_probe_link_id: Option<breakpoint::BreakpointHandle>,
    resume_actions: Vec<(Tid, ThreadAction)>,
    is_scheduler_lock: bool,
    exec_path: Option<PathBuf>,
    pub bound_pid: Option<u32>,
    pub bound_tid: Option<u32>,
    host_io_files: HashMap<u32, crate::virtual_file::VirtualFile>,
    next_host_io_fd: u32,
    pub is_multi_thread: bool,
    step_use_uprobe: bool,
    need_filter_maps: bool,
    r_debug_addr: Option<u64>,
    cached_libraries_xml: String,
}

pub const HOST_IO_FD_START: u32 = 100;

impl EdbgTarget {
    pub fn new(
        mut ebpf: Ebpf,
        is_multi_thread: bool,
        need_filter_maps: bool,
        step_use_uprobe: bool,
    ) -> Self {
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
        let notifier = ringbuf
            .as_fd()
            .try_clone_to_owned()
            .expect("failed to clone ringbuf fd");
        Self {
            ebpf,
            context: None,
            ring_buf: ringbuf,
            notifier,
            thread_filter,
            active_sw_breakpoints: HashMap::new(),
            active_hw_breakpoints: HashMap::new(),
            active_watchpoint: HashMap::new(),
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
            step_use_uprobe,
            need_filter_maps,
            r_debug_addr: None,
            cached_libraries_xml: String::new(),
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
            .ok_or(anyhow!("Target process is not running or not attached"))
    }

    pub fn get_tid(&self) -> Result<u32> {
        self.bound_tid.ok_or(anyhow!("Target bound tid is not set"))
    }

    pub fn get_process_handle(&self) -> Result<process_memory::ProcessHandle> {
        let tid = self
            .bound_tid
            .ok_or(anyhow!("Target bound tid is not set"))?;
        Ok((tid as i32, process_memory::Architecture::from_native()))
    }
}

impl Target for EdbgTarget {
    type Arch = TargetArch;
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

    #[inline(always)]
    fn support_libraries_svr4(
        &mut self,
    ) -> Option<gdbstub::target::ext::libraries::LibrariesSvr4Ops<'_, Self>> {
        Some(self)
    }
}

impl MultiThreadBase for EdbgTarget {
    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as gdbstub::arch::Arch>::Registers,
        tid: gdbstub::common::Tid,
    ) -> TargetResult<(), Self> {
        debug!("enter read register tid: {}", tid);
        if let Some(ctx) = &self.context
            && (!self.is_multi_thread || ctx.tid == tid.get() as u32)
        {
            debug!("fill registers from context");
            arch::fill_regs(regs, ctx);
            return Ok(());
        }
        debug!("fill registers from /proc syscall");
        debug!("ctx: {:?}", self.context);
        debug!("is_multi_thread: {}", self.is_multi_thread);
        debug!("requested tid: {}", tid);
        // open /proc/pid/tasks/tid/syscall to get pc
        let (sp, pc) = self.get_thread_sp_pc(tid.get() as u32).map_err(|e| {
            error!("Failed to get SP/PC for tid {}: {}", tid, e);
            TargetError::NonFatal
        })?;
        arch::fill_regs_minimal(regs, sp, pc);
        Ok(())
    }

    fn write_registers(
        &mut self,
        _regs: &<Self::Arch as gdbstub::arch::Arch>::Registers,
        _tid: gdbstub::common::Tid,
    ) -> TargetResult<(), Self> {
        warn!("write_registers not fully implemented (requires ptrace or inline hooking)");
        Err(TargetError::NonFatal)
    }

    fn read_addrs(
        &mut self,
        start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        data: &mut [u8],
        tid: gdbstub::common::Tid,
    ) -> TargetResult<usize, Self> {
        use process_memory::{CopyAddress, TryIntoProcessHandle};
        let process_handle = (tid.get() as process_memory::Pid)
            .try_into_process_handle()
            .map_err(|e| {
                error!("Failed to get process handle for tid {}: {}", tid, e);
                TargetError::NonFatal
            })?;
        match process_handle.copy_address(start_addr as usize, data) {
            Ok(_) => Ok(data.len()),
            Err(e) => {
                trace!("Failed to read memory at {:#x}: {}", start_addr, e);
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
        let path = format!("/proc/{}/mem", tid);
        use std::{
            fs::OpenOptions,
            io::{Seek, SeekFrom, Write},
        };
        let mut file = match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to open {}: {:?}", path, e);
                return Err(TargetError::Io(e));
            }
        };
        if let Err(e) = file.seek(SeekFrom::Start(start_addr)) {
            warn!("Failed to seek to {:#x}: {:?}", start_addr, e);
            return Err(TargetError::Io(e));
        }
        match file.write_all(data) {
            Ok(_) => Ok(()),
            Err(e) => {
                warn!(
                    "Failed to write memory at {:#x} via /proc/mem: {:?}",
                    start_addr, e
                );
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

    #[inline(always)]
    fn support_single_register_access(
        &mut self,
    ) -> Option<
        gdbstub::target::ext::base::single_register_access::SingleRegisterAccessOps<'_, Tid, Self>,
    > {
        Some(self)
    }
}
