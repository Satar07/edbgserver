use gdbstub::target::{TargetError, ext::exec_file::ExecFile};
use log::debug;
use procfs::process::Process;

use crate::target::EdbgTarget;

impl ExecFile for EdbgTarget {
    fn get_exec_file(
        &self,
        pid: Option<gdbstub::common::Pid>,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> gdbstub::target::TargetResult<usize, Self> {
        debug!("get exec file {:?}", pid);
        let path = if let Some(path) = &self.exec_path {
            path.clone()
        } else {
            let target_pid = pid
                .map(|p| p.get() as u32)
                .or(self.bound_pid)
                .ok_or(TargetError::NonFatal)?;

            Process::new(target_pid as i32)
                .and_then(|p| p.exe())
                .map_err(|_| TargetError::NonFatal)?
        };

        let path_str = path
            .canonicalize()
            .unwrap_or_else(|_| path.clone())
            .to_string_lossy()
            .to_string();
        let path_bytes = path_str.as_bytes();
        let total_len = path_bytes.len();
        let offset = offset as usize;

        if offset >= total_len {
            return Ok(0);
        }
        let available_len = total_len - offset;
        let copy_len = std::cmp::min(available_len, length);
        let copy_len = std::cmp::min(copy_len, buf.len());
        buf[..copy_len].copy_from_slice(&path_bytes[offset..offset + copy_len]);
        Ok(copy_len)
    }
}
