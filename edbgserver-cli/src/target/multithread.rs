use std::{collections::HashSet, ffi::OsStr, num::NonZero, os::unix::ffi::OsStrExt, process};

use anyhow::{Result, bail};
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
use log::{debug, error, info, trace};
use procfs::process::Process;

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

        let dispatch_signal = |tid: u32, signal: Option<&Signal>| {
            if let Some(sig) = signal {
                send_sig_to_thread(target_pid, tid, sig);
            } else {
                send_sigcont_to_thread(target_pid, tid);
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
                    self.single_step_thread(tid, self.context.unwrap().pc)?;
                    dispatch_signal(tid, signal.as_ref());
                }
            }
        }

        if self.is_scheduler_lock {
            debug!("Scheduler locking is enabled; not continuing other threads");
            return Ok(());
        }

        let handled_tids: HashSet<u32> = self
            .resume_actions
            .iter()
            .map(|(tid, _)| tid.get() as u32)
            .collect();

        self.get_active_threads()?
            .iter()
            .map(|t| t.get() as u32)
            .filter(|tid| !handled_tids.contains(tid))
            .for_each(|tid| {
                debug!("Continuing thread {} (implicit)", tid);
                send_sigcont_to_thread(target_pid, tid);
            });
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
        let pid = self.get_pid()? as i32;

        let process = Process::new(pid)?;

        let threads: Vec<NonZero<usize>> = process
            .tasks()?
            .flatten()
            .map(|t| NonZero::new(t.tid as usize).expect("TID 0 is invalid"))
            .collect();

        Ok(threads)
    }
}
