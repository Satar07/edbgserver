use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

pub struct ProcessMem {
    file: File,
}

impl ProcessMem {
    pub fn open(pid: i32) -> io::Result<Self> {
        let file = File::options()
            .read(true)
            .write(true)
            .open(format!("/proc/{}/mem", pid))?;
        Ok(Self { file })
    }

    pub fn read(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.file.seek(SeekFrom::Start(addr))?;
        self.file.read(buf)
    }

    pub fn write(&mut self, addr: u64, buf: &[u8]) -> io::Result<usize> {
        self.file.seek(SeekFrom::Start(addr))?;
        self.file.write(buf)
    }
}

pub fn send_sigcont(pid: i32) {
    unsafe {
        libc::kill(pid, libc::SIGCONT);
    }
}

pub fn send_sigstop(pid: i32) {
    unsafe {
        libc::kill(pid, libc::SIGSTOP);
    }
}
