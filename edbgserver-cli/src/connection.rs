use gdbstub::conn::{Connection, ConnectionExt};
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::runtime::Handle;

pub struct TokioConnection {
    pub stream: BufReader<TcpStream>,
}

impl TokioConnection {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: BufReader::new(stream),
        }
    }
}

impl Connection for TokioConnection {
    type Error = io::Error;

    fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
        Handle::current().block_on(async { self.stream.write_u8(byte).await })
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Handle::current().block_on(async { self.stream.flush().await })
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        Handle::current().block_on(async { self.stream.write_all(buf).await })
    }

    fn on_session_start(&mut self) -> Result<(), Self::Error> {
        let tcp_stream = self.stream.get_ref();
        tcp_stream.set_nodelay(true)?;
        Ok(())
    }
}

impl ConnectionExt for TokioConnection {
    fn read(&mut self) -> Result<u8, Self::Error> {
        Handle::current().block_on(async { self.stream.read_u8().await })
    }

    fn peek(&mut self) -> Result<Option<u8>, Self::Error> {
        Handle::current().block_on(async {
            let buffer = self.stream.fill_buf().await?;
            if buffer.is_empty() {
                Ok(None)
            } else {
                Ok(Some(buffer[0]))
            }
        })
    }
}
