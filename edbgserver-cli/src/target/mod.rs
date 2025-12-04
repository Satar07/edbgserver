use std::{fs, os::fd::OwnedFd};

use aya::maps::{MapData, RingBuf};
use edbgserver_common::DataT;

use gdbstub::target::ext::base::multithread::MultiThreadResumeOps;
use gdbstub::target::ext::breakpoints::BreakpointsOps;

use gdbstub::{
    common::{Signal, Tid},
    target::{
        Target, TargetError, TargetResult,
        ext::base::{
            BaseOps,
            multithread::{MultiThreadBase, MultiThreadResume},
        },
    },
};
use gdbstub_arch::aarch64::{AArch64, reg::AArch64CoreRegs};
use log::{debug, warn};
use tokio::io::unix::AsyncFd;

use crate::utils::{ProcessMem, send_sigcont};

mod breakpoint;

pub struct EdbgTarget {
    pub pid: i32,
    pub mem: ProcessMem,
    pub last_context: Option<DataT>,
    pub ring_buf: RingBuf<MapData>,
    pub notifier: AsyncFd<OwnedFd>,
    saved_breakpoints: std::collections::HashMap<u64, u8>,
}

impl EdbgTarget {
    pub fn new(
        pid: i32,
        ringbuf: RingBuf<MapData>,
        notifier: AsyncFd<OwnedFd>,
    ) -> std::io::Result<Self> {
        let mem = ProcessMem::open(pid)?;
        Ok(Self {
            pid,
            mem,
            last_context: None,
            ring_buf: ringbuf,
            notifier,
            saved_breakpoints: std::collections::HashMap::new(),
        })
    }
}

impl Target for EdbgTarget {
    type Arch = AArch64;

    type Error = &'static str;

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
        if let Some(ctx) = &self.last_context {
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
        debug!("last_context: {:?}", self.last_context);
        Ok(())
    }

    fn write_registers(
        &mut self,
        _regs: &<Self::Arch as gdbstub::arch::Arch>::Registers,
        _tid: gdbstub::common::Tid,
    ) -> TargetResult<(), Self> {
        log::warn!("write_registers not fully implemented (requires ptrace struct mapping)");
        Ok(())
    }

    fn read_addrs(
        &mut self,
        start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        data: &mut [u8],
        _tid: gdbstub::common::Tid,
    ) -> TargetResult<usize, Self> {
        self.mem.read(start_addr, data).map_err(TargetError::Io)
    }

    fn write_addrs(
        &mut self,
        start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
        data: &[u8],
        _tid: gdbstub::common::Tid,
    ) -> TargetResult<(), Self> {
        self.mem
            .write(start_addr, data)
            .map(|_| ())
            .map_err(TargetError::Io)
    }

    fn list_active_threads(
        &mut self,
        thread_is_active: &mut dyn FnMut(gdbstub::common::Tid),
    ) -> Result<(), Self::Error> {
        let path = format!("/proc/{}/task", self.pid);
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
        // GDB 告诉我们继续运行。
        // 我们需要向目标进程发送 SIGCONT。
        debug!("Resuming process {}", self.pid);

        // 这里只是简单的发信号。在 eBPF 场景下，单步调试(Step)比较复杂，
        // 通常需要 PTRACE_SINGLESTEP。这里为了简单，我们把 Step 也处理为 Continue，
        // 或者你可以根据 self.resume_actions 区分处理。

        send_sigcont(self.pid);

        // 清除上下文缓存，因为程序运行后寄存器就变了
        self.last_context = None;

        Ok(())
    }

    fn clear_resume_actions(&mut self) -> Result<(), Self::Error> {
        // 可以在这里清空内部记录的 actions 列表
        Ok(())
    }

    fn set_resume_action_continue(
        &mut self,
        _tid: Tid,
        _signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        // 记录该线程需要继续运行
        // 这里的简化版只需要在 resume() 里统一处理
        Ok(())
    }
}
