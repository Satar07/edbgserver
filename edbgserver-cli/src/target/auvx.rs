use std::fs::File;
use std::os::unix::fs::FileExt;

use gdbstub::target::{TargetError, TargetResult, ext::auxv::Auxv};
use log::{debug, error};

use crate::target::EdbgTarget;

impl Auxv for EdbgTarget {
    fn get_auxv(&self, offset: u64, length: usize, buf: &mut [u8]) -> TargetResult<usize, Self> {
        let pid = self.get_pid().map_err(|_| {
            error!("failed to get pid in get auxv");
            TargetError::NonFatal
        })?;
        let path = format!("/proc/{}/auxv", pid);
        debug!("get auxv: {}", path);
        let auvx_file = File::open(path).map_err(|e| {
            error!("failed to open auvx file: {}", e);
            TargetError::NonFatal
        })?;
        let len = std::cmp::min(length, buf.len());
        match auvx_file.read_at(&mut buf[..len], offset) {
            Ok(n) => Ok(n),
            Err(e) => Err(e.into()),
        }
    }
}
