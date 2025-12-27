use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};

use gdbstub::target::ext::host_io::{
    HostIo, HostIoClose, HostIoCloseOps, HostIoErrno, HostIoError, HostIoFstat, HostIoFstatOps,
    HostIoOpen, HostIoOpenFlags, HostIoOpenMode, HostIoOpenOps, HostIoPread, HostIoPreadOps,
    HostIoPwrite, HostIoPwriteOps, HostIoReadlink, HostIoReadlinkOps, HostIoResult, HostIoStat,
    HostIoUnlink, HostIoUnlinkOps,
};
use log::debug;

use crate::{target::EdbgTarget, virtual_file::VirtualFile};

impl HostIo for EdbgTarget {
    #[inline(always)]
    fn support_open(&mut self) -> Option<HostIoOpenOps<'_, Self>> {
        Some(self)
    }
    #[inline(always)]
    fn support_close(&mut self) -> Option<HostIoCloseOps<'_, Self>> {
        Some(self)
    }
    #[inline(always)]
    fn support_pread(&mut self) -> Option<HostIoPreadOps<'_, Self>> {
        Some(self)
    }
    #[inline(always)]
    fn support_pwrite(&mut self) -> Option<HostIoPwriteOps<'_, Self>> {
        Some(self)
    }
    #[inline(always)]
    fn support_fstat(&mut self) -> Option<HostIoFstatOps<'_, Self>> {
        Some(self)
    }
    #[inline(always)]
    fn support_readlink(&mut self) -> Option<HostIoReadlinkOps<'_, Self>> {
        Some(self)
    }
    #[inline(always)]
    fn support_unlink(&mut self) -> Option<HostIoUnlinkOps<'_, Self>> {
        Some(self)
    }
}

impl HostIoOpen for EdbgTarget {
    fn open(
        &mut self,
        filename: &[u8],
        flags: HostIoOpenFlags,
        mode: HostIoOpenMode,
    ) -> HostIoResult<u32, Self> {
        match VirtualFile::open(filename, flags, mode) {
            Ok(vfile) => {
                let fd = self.next_host_io_fd;
                self.next_host_io_fd = fd
                    .checked_add(1)
                    .ok_or(HostIoError::Errno(HostIoErrno::EMFILE))?;

                self.host_io_files.insert(fd, vfile);

                debug!("HostIo: Opened fd={} (flags={:?})", fd, flags);
                Ok(fd)
            }
            Err(e) => Err(HostIoError::from(e)),
        }
    }
}

impl HostIoClose for EdbgTarget {
    fn close(&mut self, fd: u32) -> HostIoResult<(), Self> {
        if self.host_io_files.remove(&fd).is_some() {
            debug!("HostIo: Closed fd={}", fd);
            Ok(())
        } else {
            Err(HostIoError::Errno(HostIoErrno::EBADF))
        }
    }
}

impl HostIoPread for EdbgTarget {
    fn pread(
        &mut self,
        fd: u32,
        count: usize,
        offset: u64,
        buf: &mut [u8],
    ) -> HostIoResult<usize, Self> {
        let file = self
            .host_io_files
            .get_mut(&fd)
            .ok_or(HostIoError::Errno(HostIoErrno::EBADF))?;

        let len = std::cmp::min(count, buf.len());
        file.read_at(offset, &mut buf[..len])
            .map_err(HostIoError::from)
    }
}

impl HostIoPwrite for EdbgTarget {
    fn pwrite(&mut self, fd: u32, offset: u64, data: &[u8]) -> HostIoResult<u64, Self> {
        let file = self
            .host_io_files
            .get_mut(&fd)
            .ok_or(HostIoError::Errno(HostIoErrno::EBADF))?;

        file.write_at(offset, data).map_err(HostIoError::from)
    }
}

impl HostIoFstat for EdbgTarget {
    fn fstat(&mut self, fd: u32) -> HostIoResult<HostIoStat, Self> {
        let file = self
            .host_io_files
            .get(&fd)
            .ok_or(HostIoError::Errno(HostIoErrno::EBADF))?;

        file.stat().map_err(HostIoError::from)
    }
}

impl HostIoReadlink for EdbgTarget {
    fn readlink(&mut self, filename: &[u8], buf: &mut [u8]) -> HostIoResult<usize, Self> {
        let path = Path::new(OsStr::from_bytes(filename));
        let target = std::fs::read_link(path).map_err(HostIoError::from)?;
        let bytes = target.as_os_str().as_bytes();
        let len = std::cmp::min(bytes.len(), buf.len());
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(len)
    }
}

impl HostIoUnlink for EdbgTarget {
    fn unlink(&mut self, filename: &[u8]) -> HostIoResult<(), Self> {
        std::fs::remove_file(Path::new(OsStr::from_bytes(filename))).map_err(HostIoError::from)
    }
}
