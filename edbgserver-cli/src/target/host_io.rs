use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use gdbstub::target::ext::host_io::{
    HostIo, HostIoClose, HostIoCloseOps, HostIoErrno, HostIoError, HostIoFstat, HostIoFstatOps,
    HostIoOpen, HostIoOpenFlags, HostIoOpenMode, HostIoOpenOps, HostIoPread, HostIoPreadOps,
    HostIoPwrite, HostIoPwriteOps, HostIoReadlink, HostIoReadlinkOps, HostIoResult, HostIoStat,
    HostIoUnlink, HostIoUnlinkOps,
};

use crate::target::EdbgTarget;

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
        let path = Path::new(OsStr::from_bytes(filename));
        let mut options = OpenOptions::new();
        if flags.contains(HostIoOpenFlags::O_RDONLY) {
            options.read(true);
        }
        if flags.contains(HostIoOpenFlags::O_WRONLY) {
            options.write(true);
        }
        if flags.contains(HostIoOpenFlags::O_RDWR) {
            options.read(true).write(true);
        }
        if flags.contains(HostIoOpenFlags::O_CREAT) {
            options.create(true);
        }
        if flags.contains(HostIoOpenFlags::O_EXCL) {
            options.create_new(true);
        }
        if flags.contains(HostIoOpenFlags::O_TRUNC) {
            options.truncate(true);
        }
        if flags.contains(HostIoOpenFlags::O_APPEND) {
            options.append(true);
        }

        options.mode(mode.bits());
        match options.open(path) {
            Ok(file) => {
                let fd = self.next_host_io_fd;
                self.next_host_io_fd = self
                    .next_host_io_fd
                    .checked_add(1)
                    .ok_or(HostIoError::Errno(HostIoErrno::EMFILE))?;
                self.host_io_files.insert(fd, file);
                Ok(fd)
            }
            Err(e) => Err(HostIoError::from(e)),
        }
    }
}

impl HostIoClose for EdbgTarget {
    fn close(&mut self, fd: u32) -> HostIoResult<(), Self> {
        match self.host_io_files.remove(&fd) {
            Some(_) => Ok(()),
            None => Err(HostIoError::Errno(HostIoErrno::EBADF)),
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
        if let Some(file) = self.host_io_files.get(&fd) {
            let len = std::cmp::min(count, buf.len());
            match file.read_at(&mut buf[..len], offset) {
                Ok(n) => Ok(n),
                Err(e) => Err(HostIoError::from(e)),
            }
        } else {
            Err(HostIoError::Errno(HostIoErrno::EBADF))
        }
    }
}

impl HostIoPwrite for EdbgTarget {
    fn pwrite(
        &mut self,
        fd: u32,
        offset: <Self::Arch as gdbstub::arch::Arch>::Usize,
        data: &[u8],
    ) -> HostIoResult<<Self::Arch as gdbstub::arch::Arch>::Usize, Self> {
        if let Some(file) = self.host_io_files.get(&fd) {
            match file.write_at(data, offset) {
                Ok(n) => Ok(n as <Self::Arch as gdbstub::arch::Arch>::Usize),
                Err(e) => Err(HostIoError::from(e)),
            }
        } else {
            Err(HostIoError::Errno(HostIoErrno::EBADF))
        }
    }
}

impl HostIoFstat for EdbgTarget {
    fn fstat(&mut self, fd: u32) -> HostIoResult<HostIoStat, Self> {
        if let Some(file) = self.host_io_files.get(&fd) {
            match file.metadata() {
                Ok(m) => Ok(HostIoStat {
                    st_dev: m.dev() as u32,
                    st_ino: m.ino() as u32,
                    st_mode: HostIoOpenMode::from_bits_truncate(m.mode()),
                    st_nlink: m.nlink() as u32,
                    st_uid: m.uid(),
                    st_gid: m.gid(),
                    st_rdev: m.rdev() as u32,
                    st_size: m.size(),
                    st_blksize: m.blksize(),
                    st_blocks: m.blocks(),
                    st_atime: m.atime() as u32,
                    st_mtime: m.mtime() as u32,
                    st_ctime: m.ctime() as u32,
                }),
                Err(e) => Err(HostIoError::from(e)),
            }
        } else {
            Err(HostIoError::Errno(HostIoErrno::EBADF))
        }
    }
}

impl HostIoReadlink for EdbgTarget {
    fn readlink(&mut self, filename: &[u8], buf: &mut [u8]) -> HostIoResult<usize, Self> {
        let path = Path::new(OsStr::from_bytes(filename));
        match std::fs::read_link(path) {
            Ok(target_path) => {
                let bytes = target_path.as_os_str().as_bytes();
                let len = std::cmp::min(bytes.len(), buf.len());
                buf[..len].copy_from_slice(&bytes[..len]);
                Ok(len)
            }
            Err(e) => Err(HostIoError::from(e)),
        }
    }
}

impl HostIoUnlink for EdbgTarget {
    fn unlink(&mut self, filename: &[u8]) -> HostIoResult<(), Self> {
        let path = Path::new(OsStr::from_bytes(filename));
        match std::fs::remove_file(path) {
            Ok(_) => Ok(()),
            Err(e) => Err(HostIoError::from(e)),
        }
    }
}
