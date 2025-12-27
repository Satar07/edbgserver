use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{Cursor, Read, Seek, SeekFrom},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

use gdbstub::target::ext::host_io::*;
use log::debug;

trait MetadataToHostIoStat {
    fn to_gdb_stat(&self) -> HostIoStat;
}

impl MetadataToHostIoStat for std::fs::Metadata {
    fn to_gdb_stat(&self) -> HostIoStat {
        HostIoStat {
            st_dev: self.dev() as u32,
            st_ino: self.ino() as u32,
            st_mode: HostIoOpenMode::from_bits_truncate(self.mode()),
            st_nlink: self.nlink() as u32,
            st_uid: self.uid(),
            st_gid: self.gid(),
            st_rdev: self.rdev() as u32,
            st_size: self.size(),
            st_blksize: self.blksize(),
            st_blocks: self.blocks(),
            st_atime: self.atime() as u32,
            st_mtime: self.mtime() as u32,
            st_ctime: self.ctime() as u32,
        }
    }
}

pub enum VirtualFile {
    Real(File),
    Cached { data: Cursor<Vec<u8>> },
}

impl VirtualFile {
    pub fn open(
        filename: &[u8],
        flags: HostIoOpenFlags,
        mode: HostIoOpenMode,
    ) -> std::io::Result<Self> {
        let path = Path::new(OsStr::from_bytes(filename));
        let path_str = path.to_string_lossy();

        debug!(
            "VirtualFile: Request open '{}' (flags={:?}, mode={:?})",
            path_str, flags, mode
        );

        if flags == HostIoOpenFlags::O_RDONLY {
            debug!("VirtualFile: HIT CACHE STRATEGY for '{}'", path_str);
            let data = std::fs::read(path)?;
            return Ok(VirtualFile::Cached {
                data: Cursor::new(data),
            });
        }

        let mut options = OpenOptions::new();
        options
            .read(
                flags.contains(HostIoOpenFlags::O_RDONLY)
                    || flags.contains(HostIoOpenFlags::O_RDWR),
            )
            .write(
                flags.contains(HostIoOpenFlags::O_WRONLY)
                    || flags.contains(HostIoOpenFlags::O_RDWR),
            )
            .create(flags.contains(HostIoOpenFlags::O_CREAT))
            .create_new(flags.contains(HostIoOpenFlags::O_EXCL))
            .truncate(flags.contains(HostIoOpenFlags::O_TRUNC))
            .append(flags.contains(HostIoOpenFlags::O_APPEND))
            .mode(mode.bits());

        let file = options.open(path)?;
        Ok(VirtualFile::Real(file))
    }

    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            VirtualFile::Real(file) => {
                debug!(
                    "VirtualFile: read real file off={} len={}",
                    offset,
                    buf.len()
                );
                file.read_at(buf, offset)
            }
            VirtualFile::Cached { data, .. } => {
                debug!(
                    "VirtualFile: Cached read_at off={} len={}",
                    offset,
                    buf.len()
                );
                data.seek(SeekFrom::Start(offset))?;
                data.read(buf)
            }
        }
    }

    pub fn write_at(&mut self, offset: u64, buf: &[u8]) -> std::io::Result<u64> {
        debug!("VirtualFile: write_at off={} len={}", offset, buf.len());
        match self {
            VirtualFile::Real(file) => file.write_at(buf, offset).map(|n| n as u64),
            VirtualFile::Cached { .. } => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Cannot write to cached file",
            )),
        }
    }

    pub fn stat(&self) -> std::io::Result<HostIoStat> {
        match self {
            VirtualFile::Real(file) => {
                let meta = file.metadata()?;
                Ok(meta.to_gdb_stat())
            }
            VirtualFile::Cached { data, .. } => {
                let len = data.get_ref().len() as u64;
                Ok(HostIoStat {
                    st_dev: 0,
                    st_ino: 0,
                    st_mode: HostIoOpenMode::S_IFREG | HostIoOpenMode::S_IRUSR,
                    st_nlink: 1,
                    st_uid: 0,
                    st_gid: 0,
                    st_rdev: 0,
                    st_size: len,
                    st_blksize: 4096,
                    st_blocks: len.div_ceil(512),
                    st_atime: 0,
                    st_mtime: 0,
                    st_ctime: 0,
                })
            }
        }
    }
}
