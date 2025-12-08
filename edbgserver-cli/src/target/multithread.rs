use std::{collections::HashSet, num::NonZero};

use anyhow::Result;
use gdbstub::{
    common::{Signal, Tid},
    target::ext::base::multithread::{MultiThreadResume, MultiThreadSingleStep},
};
use log::{debug, info};
use procfs::process::Process;

use crate::{
    target::EdbgTarget,
    utils::{send_sig, send_sigcont},
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
        debug!("set resume action step for TID {:?}", tid);
        self.resume_actions.push((tid, ThreadAction::Step(signal)));
        Ok(())
    }
}

impl MultiThreadResume for EdbgTarget {
    fn clear_resume_actions(&mut self) -> Result<(), Self::Error> {
        debug!("clear resume actions");
        self.resume_actions.clear();
        Ok(())
    }

    fn set_resume_action_continue(
        &mut self,
        tid: Tid,
        signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        debug!("set resume action continue for TID {:?}", tid);
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

    fn resume(&mut self) -> Result<(), Self::Error> {
        let target_pid = self.get_pid()?;
        debug!("Resuming process {}", target_pid);

        let dispatch_signal = |tid: u32, signal: Option<&Signal>| {
            if let Some(sig) = signal {
                send_sig(tid, sig);
            } else {
                send_sigcont(tid);
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
                    self.single_step_thread(tid)?; // 可能会出错，保留 ?
                    dispatch_signal(tid, signal.as_ref());
                }
            }
        }

        let handled_tids: HashSet<u32> = self
            .resume_actions
            .iter()
            .map(|(tid, _)| tid.get() as u32)
            .collect();

        self.cached_threads
            .take()
            .iter()
            .flatten()
            .map(|t| t.get() as u32)
            .filter(|tid| !handled_tids.contains(tid))
            .for_each(|tid| {
                debug!("Continuing thread {} (implicit)", tid);
                send_sigcont(tid);
            });
        Ok(())
    }
}

impl EdbgTarget {
    pub fn get_active_threads(&mut self) -> Result<&[NonZero<usize>]> {
        if self.cached_threads.is_none() {
            self.refresh_thread_cache()?;
        }

        Ok(self.cached_threads.as_ref().unwrap().as_slice())
    }

    fn refresh_thread_cache(&mut self) -> Result<()> {
        debug!("Refreshing thread cache from /proc");

        if self.context.is_none() {
            self.cached_threads = Some(Vec::new());
            return Ok(());
        }

        let pid = self.get_pid()? as i32;

        let process = Process::new(pid)?;

        let threads: Vec<NonZero<usize>> = process
            .tasks()?
            .flatten()
            .map(|t| NonZero::new(t.tid as usize).expect("TID 0 is invalid"))
            .collect();

        self.cached_threads = Some(threads);
        Ok(())
    }
}
