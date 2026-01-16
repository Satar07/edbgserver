use std::{
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    net::TcpStream,
    os::{fd::AsFd, unix::net::UnixStream},
};

pub struct BufferedConnection {
    stream_reader: BufReader<GdbStream>,
    stream_writer: BufWriter<GdbStream>,
}

pub enum GdbStream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Read for GdbStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            Self::Unix(s) => s.read(buf),
        }
    }
}

impl Write for GdbStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            Self::Unix(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            Self::Unix(s) => s.flush(),
        }
    }
}

impl AsFd for GdbStream {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        match self {
            Self::Tcp(s) => s.as_fd(),
            Self::Unix(s) => s.as_fd(),
        }
    }
}

impl GdbStream {
    pub fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Tcp(s) => Ok(Self::Tcp(s.try_clone()?)),
            Self::Unix(s) => Ok(Self::Unix(s.try_clone()?)),
        }
    }
}

impl BufferedConnection {
    pub fn new(stream: GdbStream) -> io::Result<Self> {
        if let GdbStream::Tcp(ref tcp) = stream {
            tcp.set_nodelay(true)?;
        }

        let writer_stream = stream.try_clone()?;
        Ok(Self {
            stream_reader: BufReader::with_capacity(4096, stream),
            stream_writer: BufWriter::with_capacity(4096, writer_stream),
        })
    }

    pub fn has_buffered_data(&self) -> bool {
        !self.stream_reader.buffer().is_empty()
    }
}

impl gdbstub::conn::Connection for BufferedConnection {
    type Error = io::Error;

    fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
        self.stream_writer.write_all(&[byte])
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.stream_writer.write_all(buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl gdbstub::conn::ConnectionExt for BufferedConnection {
    fn read(&mut self) -> Result<u8, Self::Error> {
        self.stream_writer.flush()?;
        let mut buf = [0u8; 1];
        self.stream_reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn peek(&mut self) -> Result<Option<u8>, Self::Error> {
        self.stream_writer.flush()?;
        let buf = self.stream_reader.fill_buf()?;
        if buf.is_empty() {
            return Ok(None);
        }
        Ok(Some(buf[0]))
    }
}

impl AsFd for BufferedConnection {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.stream_reader.get_ref().as_fd()
    }
}
