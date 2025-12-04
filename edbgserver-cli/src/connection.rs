use gdbstub::conn::{Connection, ConnectionExt};
use std::io;
use tokio::net::TcpStream;
use tokio::runtime::Handle;
// 关键点：必须引入这两个扩展 Trait 才能使用 write_u8, read_u8, peek 等方法
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct TokioConnection {
    pub stream: TcpStream,
}

impl TokioConnection {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
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
}

impl ConnectionExt for TokioConnection {
    fn read(&mut self) -> Result<u8, Self::Error> {
        Handle::current().block_on(async { self.stream.read_u8().await })
    }

    fn peek(&mut self) -> Result<Option<u8>, Self::Error> {
        let mut buf = [0; 1];
        Handle::current().block_on(async {
            let n = self.stream.peek(&mut buf).await?;
            if n == 0 { Ok(None) } else { Ok(Some(buf[0])) }
        })
    }
}
