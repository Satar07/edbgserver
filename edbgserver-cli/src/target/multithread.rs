use std::{collections::HashSet, ffi::OsStr, num::NonZero, os::unix::ffi::OsStrExt, process};

use anyhow::{Context, Result, anyhow, bail};
use gdbstub::{
    common::{Signal, Tid},
    target::{
        TargetError, TargetResult,
        ext::{
            base::multithread::{
                MultiThreadResume, MultiThreadSchedulerLocking, MultiThreadSingleStep,
            },
            extended_mode::{CurrentActivePid, ExtendedMode, ShouldTerminate},
        },
    },
};
use log::{debug, error, info, trace, warn};

use crate::{
    target::EdbgTarget,
    utils::{send_sig_to_process, send_sig_to_thread, send_sigcont_to_thread},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadAction {
    Continue(Option<Signal>),
    Step(Option<Signal>),
}

impl MultiThreadSingleStep for EdbgTarget {
    fn set_resume_action_step(
        &mut self,
        tid: Tid,
        signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        debug!("set resume action step for TID: {}", tid);
        self.resume_actions.push((tid, ThreadAction::Step(signal)));
        Ok(())
    }
}

impl MultiThreadSchedulerLocking for EdbgTarget {
    fn set_resume_action_scheduler_lock(&mut self) -> Result<(), Self::Error> {
        self.is_scheduler_lock = true;
        Ok(())
    }
}

impl MultiThreadResume for EdbgTarget {
    fn clear_resume_actions(&mut self) -> Result<(), Self::Error> {
        debug!("clear resume actions");
        self.resume_actions.clear();
        self.is_scheduler_lock = false;

        while self.ring_buf.next().is_some() {
            warn!("Draining stale event from ring buffer before resume");
        }
        Ok(())
    }

    fn set_resume_action_continue(
        &mut self,
        tid: Tid,
        signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        debug!("set resume action continue for TID: {}", tid);
        self.resume_actions
            .push((tid, ThreadAction::Continue(signal)));
        Ok(())
    }

    #[inline(always)]
    fn support_single_step(
        &mut self,
    ) -> Option<gdbstub::target::ext::base::multithread::MultiThreadSingleStepOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_scheduler_locking(
        &mut self,
    ) -> Option<gdbstub::target::ext::base::multithread::MultiThreadSchedulerLockingOps<'_, Self>>
    {
        Some(self)
    }

    fn resume(&mut self) -> Result<(), Self::Error> {
        let target_pid = self.get_pid()?;
        debug!("start handling resuming process {}", target_pid);

        if self.is_scheduler_lock
            && self.is_multi_thread
            && let Some((tid, _)) = self.resume_actions.first()
        {
            // here we assume the first resume action is the scheduler lock thread...
            // it seems gdb will only send one resume action with scheduler lock
            debug!("Setting eBPF thread filter for TID: {}", tid);
            if let Err(e) = self.thread_filter.set(
                0,
                edbgserver_common::ThreadFilter::Some(tid.get() as u32),
                0,
            ) {
                warn!("Failed to set thread filter: {}", e);
            }
        }

        let mut done_cont: HashSet<u32> = HashSet::new();

        let mut dispatch_signal = |tid: u32, signal: Option<&Signal>| {
            if let Some(sig) = signal {
                send_sig_to_thread(target_pid, tid, sig);
            } else {
                send_sigcont_to_thread(target_pid, tid);
                done_cont.insert(tid);
            }
        };

        for (tid, action) in &self.resume_actions.clone() {
            let tid = tid.get() as u32;
            match action {
                ThreadAction::Continue(signal) => {
                    debug!("Continuing thread {} with signal {:?}", tid, signal);
                    dispatch_signal(tid, signal.as_ref());
                }
                ThreadAction::Step(signal) => {
                    info!("Single stepping thread {} with signal {:?}", tid, signal);
                    let (_sp, pc) = match self.get_thread_sp_pc(tid) {
                        Ok(sp_pc) => sp_pc,
                        Err(e) => {
                            warn!(
                                "Failed to get PC for TID {}: {}. Falling back to continue.",
                                tid, e
                            );
                            dispatch_signal(tid, signal.as_ref());
                            continue;
                        }
                    };
                    self.single_step_thread(tid, pc)?;
                    dispatch_signal(tid, signal.as_ref());
                }
            }
        }

        if self.is_scheduler_lock {
            debug!("Scheduler locking is enabled; not continuing other threads");
            return Ok(());
        }

        if let Some(tid) = self.get_tid().ok()
            && !done_cont.contains(&tid)
        {
            debug!("implicitly continue thread {}", tid);
            send_sigcont_to_thread(target_pid, tid);
        } else {
            debug!("no target need implicitly continue");
        }
        Ok(())
    }
}

impl ExtendedMode for EdbgTarget {
    fn run(
        &mut self,
        filename: Option<&[u8]>,
        args: gdbstub::target::ext::extended_mode::Args<'_, '_>,
    ) -> TargetResult<gdbstub::common::Pid, Self> {
        info!("run command");
        if let Some(filename) = filename {
            let filename = OsStr::from_bytes(filename);
            let mut cmd = process::Command::new(filename);
            for arg in args {
                cmd.arg(OsStr::from_bytes(arg));
            }
            debug!("Spawning process: {:?}", cmd);
            let handle = cmd.spawn()?;
            self.bound_pid = Some(handle.id());
            let pid =
                gdbstub::common::Pid::new(handle.id() as usize).ok_or(TargetError::NonFatal)?;
            Ok(pid)
        } else if let Some(exec_path) = self.exec_path.as_ref() {
            debug!("Start process {:?}", exec_path);
            let mut cmd = process::Command::new(exec_path);
            let handle = cmd.spawn()?;
            self.bound_pid = Some(handle.id());
            let pid =
                gdbstub::common::Pid::new(handle.id() as usize).ok_or(TargetError::NonFatal)?;
            debug!("Spawned process with PID {:?}", pid);
            Ok(pid)
        } else {
            error!("No filename provided and no existing process to run");
            Err(TargetError::NonFatal)
        }
    }

    fn attach(&mut self, pid: gdbstub::common::Pid) -> TargetResult<(), Self> {
        debug!("attach to pid {}", pid);
        Ok(())
    }

    fn query_if_attached(
        &mut self,
        pid: gdbstub::common::Pid,
    ) -> TargetResult<gdbstub::target::ext::extended_mode::AttachKind, Self> {
        if let Ok(current_pid) = self.get_pid()
            && current_pid as usize == pid.get()
        {
            debug!("Already attached to pid {}", pid);
            return Ok(gdbstub::target::ext::extended_mode::AttachKind::Attach);
        }
        Err(TargetError::NonFatal)
    }

    fn kill(&mut self, pid: Option<gdbstub::common::Pid>) -> TargetResult<ShouldTerminate, Self> {
        info!("Killing target process");
        if let Some(pid) = pid {
            debug!("Sending SIGKILL to process {}", pid.get());
            send_sig_to_process(pid.get() as u32, &Signal::SIGKILL);
            self.context.take();
            Ok(ShouldTerminate::No)
        } else if let Ok(pid) = self
            .get_pid()
            .map_err(|_| -> TargetError<Self::Error> { TargetError::NonFatal })
        {
            send_sig_to_process(pid, &Signal::SIGKILL);
            debug!("Sent SIGKILL to process {}", pid);
            self.context.take();
            Ok(ShouldTerminate::No)
        } else {
            debug!("No target process to kill");
            Err(TargetError::NonFatal)
        }
    }

    fn restart(&mut self) -> Result<(), Self::Error> {
        if let Ok(pid) = self
            .get_pid()
            .map_err(|_| -> TargetError<Self::Error> { TargetError::NonFatal })
        {
            debug!("Restarting process {}", pid);
            send_sig_to_process(pid, &Signal::SIGTERM);
            let exe = self
                .exec_path
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no exec path to restart"))?;
            let mut cmd = process::Command::new(exe);
            let handle = cmd.spawn()?;
            self.bound_pid = Some(handle.id());
            return Ok(());
        }
        bail!("failed to restart")
    }

    #[inline(always)]
    fn support_current_active_pid(
        &mut self,
    ) -> Option<gdbstub::target::ext::extended_mode::CurrentActivePidOps<'_, Self>> {
        Some(self)
    }
}

impl CurrentActivePid for EdbgTarget {
    fn current_active_pid(&mut self) -> Result<gdbstub::common::Pid, Self::Error> {
        trace!("Getting current active PID");
        let pid = self.get_pid()?;
        Ok(gdbstub::common::Pid::new(pid as usize).unwrap())
    }
}

impl EdbgTarget {
    pub fn get_active_threads(&self) -> Result<Vec<NonZero<usize>>> {
        let pid = self.get_pid()?;
        let tasks = if self.is_multi_thread {
            procfs::process::Process::new(pid as i32)
                .map_err(|e| anyhow::anyhow!("Failed to open process {}: {}", pid, e))?
                .tasks()?
                .filter_map(|t| t.ok())
                .filter(|t| {
                    t.status()
                        .map(|s| !s.state.starts_with("Z") && !s.state.starts_with("X"))
                        .unwrap_or(false)
                })
                .map(|t| NonZero::new(t.tid as usize).unwrap())
                .collect::<Vec<_>>()
        } else {
            vec![NonZero::new(self.get_tid()? as usize).unwrap()]
        };
        Ok(tasks)
    }

    pub fn get_thread_sp_pc(&self, tid: u32) -> Result<(u64, u64)> {
        let parse_hex = |s: &str| -> u64 {
            u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("-"), 16)
                .unwrap_or_else(|e| {
                    error!("Failed to parse hex: {}. String: {}", e, s);
                    0
                })
        };
        let nums: Vec<_> = std::fs::read_to_string(format!("/proc/{}/syscall", tid))?
            .split_whitespace()
            .map(parse_hex)
            .collect();
        match nums.as_slice() {
            [.., sp, pc] => Ok((*sp, *pc)),
            _ => bail!("invalid syscall content"),
        }
    }

    fn single_step_thread(&mut self, tid: u32, curr_pc: u64) -> Result<()> {
        let next_pc = self
            .calculation_next_pc(curr_pc)
            .map_err(|e| anyhow!("Failed to calculate next PC for single step: {}", e))?;
        debug!("Next PC calculated: {:#x}", next_pc);
        if self.active_sw_breakpoints.contains_key(&next_pc)
            || self.active_hw_breakpoints.contains_key(&next_pc)
        {
            return Ok(());
        }
        if self.is_multi_thread {
            self.thread_filter
                .set(0, edbgserver_common::ThreadFilter::Some(tid), 0)
                .context(anyhow!("thread filter set failed"))?;
        }

        let attach_res = if self.step_use_uprobe {
            self.internel_attach_uprobe(next_pc, Some(tid))
        } else {
            self.internel_attach_perf_event_break_point(next_pc, Some(tid))
        };

        match attach_res {
            Ok(link_id) => {
                info!("Successfully attached step breakpoint at {:#x}", next_pc);
                self.temp_step_breakpoints = Some((next_pc, link_id));
            }
            Err(e) => {
                info!(
                    "Failed to attach step breakpoint at {:#x}: {}. Checking for special cases...",
                    next_pc, e
                );
                if next_pc == curr_pc {
                    bail!(
                        "Stuck in a loop: Cannot attach breakpoint at {:#x} and next PC is same.",
                        next_pc
                    );
                }
                info!(
                    "Skipping un-attachable instruction at {:#x}, recursively stepping...",
                    next_pc
                );
                self.single_step_thread(tid, next_pc)?;
            }
        }
        Ok(())
    }
}
