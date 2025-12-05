use std::collections::HashMap;
use std::{fs, os::fd::OwnedFd};

use anyhow::{Result, anyhow};
use aya::{
    Ebpf,
    maps::{MapData, RingBuf},
    programs::{UProbe, uprobe::UProbeLinkId},
};
use edbgserver_common::DataT;
use gdbstub::{
    common::{Signal, Tid},
    target::{
        Target, TargetError, TargetResult,
        ext::{
            base::{
                BaseOps,
                multithread::{MultiThreadBase, MultiThreadResume, MultiThreadResumeOps},
            },
            breakpoints::BreakpointsOps,
        },
    },
};
use gdbstub_arch::aarch64::{AArch64, reg::AArch64CoreRegs};
use log::{debug, error, info, warn};
use std::os::fd::AsFd;
use tokio::io::{Interest, unix::AsyncFd};

use crate::utils::send_sigcont;

mod breakpoint;

pub struct EdbgTarget {
    ebpf: Ebpf,
    pub context: Option<DataT>,
    pub ring_buf: RingBuf<MapData>,
    pub notifier: AsyncFd<OwnedFd>,
    active_breakpoints: HashMap<u64, UProbeLinkId>,
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
        if let Some(ctx) = self.context {
            Ok(ctx.pid)
        } else {
            error!("No target PID set");
            Err(anyhow!("No target PID set"))
        }
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
}

impl MultiThreadBase for EdbgTarget {
    fn read_registers(
        &mut self,
        regs: &mut AArch64CoreRegs,
        tid: gdbstub::common::Tid,
    ) -> TargetResult<(), Self> {
        if let Some(ctx) = &self.context {
            if ctx.pid == tid.get() as u32 {
                // POSIX:tid -> Kernel:LWP ID(pid)
                regs.x = ctx.regs;
                regs.pc = ctx.pc;
                regs.sp = ctx.sp;
                regs.cpsr = ctx.pstate as u32;
                return Ok(());
            } else {
                debug!("Req regs for TID {} but context is for {}", tid, ctx.pid);
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
        warn!("write_registers not fully implemented (requires ptrace struct mapping)");
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
                warn!("Failed to read memory at {:#x}: {}", start_addr, e);
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
        if self.context.is_none() {
            warn!("No context available to list active threads, skip active check");
            return Ok(());
        }
        let path = format!("/proc/{}/task", self.context.unwrap().pid);
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if let Ok(fname) = entry.file_name().into_string()
                    && let Ok(tid_val) = fname.parse::<u32>()
                    && let Some(tid) = Tid::new(tid_val as usize)
                {
                    thread_is_active(tid);
                }
            }
        }
        Ok(())
    }

    #[inline(always)]
    fn support_resume(&mut self) -> Option<MultiThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl MultiThreadResume for EdbgTarget {
    fn resume(&mut self) -> Result<(), Self::Error> {
        info!("resume multithread process");
        let target_pid = self.get_pid()?;
        debug!("Resuming process {}", target_pid);
        send_sigcont(target_pid);
        Ok(())
    }

    fn clear_resume_actions(&mut self) -> Result<(), Self::Error> {
        info!("clear resume actions");
        Ok(())
    }

    fn set_resume_action_continue(
        &mut self,
        tid: Tid,
        _signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        info!("set resume action continue for TID {:?}", tid);
        Ok(())
    }
}
