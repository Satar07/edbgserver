use gdbstub::{
    common::{Signal, Tid},
    target::ext::base::multithread::{MultiThreadResume, MultiThreadSingleStep},
};
use log::{debug, info};

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
        for (tid, action) in &self.resume_actions.clone() {
            let tid = tid.get() as u32;
            match action {
                ThreadAction::Continue(signal) => {
                    debug!("Continuing thread {:?} with signal {:?}", tid, signal);
                    if let Some(sig) = signal {
                        send_sig(tid, sig);
                    } else {
                        send_sigcont(tid);
                    }
                }
                ThreadAction::Step(signal) => {
                    info!("Single stepping thread {:?} with signal {:?}", tid, signal);
                    self.single_step_thread(tid)?;
                    if let Some(sig) = signal {
                        send_sig(tid, sig);
                    } else {
                        send_sigcont(tid);
                    }
                }
            }
        }
        Ok(())
    }
}
