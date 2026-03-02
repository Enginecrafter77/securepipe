use std::io::{self, Read, Write};

#[allow(dead_code)]
pub struct BufferedPipe {
    buffer: Vec<u8>,
    size: usize,
    read_ptr: usize,
    write_ptr: usize,
}

#[allow(dead_code)]
impl BufferedPipe {
    pub fn new(size: usize) -> Self {
        Self {
            buffer: vec![0; size],
            size,
            read_ptr: 0,
            write_ptr: 0,
        }
    }

    pub fn total_read(&self) -> usize {
        self.read_ptr
    }

    pub fn total_written(&self) -> usize {
        self.write_ptr
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn available(&self) -> usize {
        self.write_ptr - self.read_ptr
    }

    pub fn free(&self) -> usize {
        self.size - self.available()
    }
}

impl Read for BufferedPipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read_len = buf.len().min(self.available());
        for byte in buf.iter_mut().take(read_len) {
            *byte = self
                .buffer
                .get(self.read_ptr % self.size)
                .copied()
                .expect("Invalid index");
            self.read_ptr += 1;
        }
        Ok(read_len)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        if buf.len() > self.available() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Buffer underflow",
            ));
        }
        assert!(buf.len() <= self.available());
        self.read(buf)?;
        Ok(())
    }
}

impl Write for BufferedPipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let write_len = buf.len().min(self.free());
        for byte in buf.iter().take(write_len) {
            let slot = self
                .buffer
                .get_mut(self.write_ptr % self.size)
                .expect("Invalid index");
            *slot = *byte;
            self.write_ptr += 1;
        }
        Ok(write_len)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if buf.len() > self.free() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "Buffer overflow"));
        }
        self.write(buf)?;
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // NOOP
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};

    use rand::{TryRngCore, rngs::OsRng};

    use crate::buffer::BufferedPipe;

    #[test]
    fn test_buffered_pipe_simple() {
        let mut orig = [0u8; 32];
        let mut piped = [0u8; 32];
        OsRng.try_fill_bytes(&mut orig).expect("RNG failed");

        let mut pipe = BufferedPipe::new(256);

        pipe.write_all(&orig).expect("Pipe write failed");
        pipe.read_exact(&mut piped).expect("Pipe read failed");
        assert_eq!(orig, piped);
    }

    #[test]
    fn test_buffered_pipe_looping() {
        let mut orig = [0u8; 32];
        let mut piped = [0u8; 32];
        OsRng.try_fill_bytes(&mut orig).expect("RNG failed");

        let mut pipe = BufferedPipe::new(256);

        for _ in 0..16 {
            pipe.write_all(&orig).expect("Pipe write failed");
            pipe.read_exact(&mut piped).expect("Pipe read failed");
            assert_eq!(orig, piped);
        }
    }

    #[test]
    fn test_buffered_pipe_overflow_cap() {
        let orig = [42u8; 32];

        let mut pipe = BufferedPipe::new(16);
        let written = pipe.write(&orig).expect("Pipe write failed");

        assert_eq!(written, 16);
    }

    #[test]
    fn test_buffered_pipe_overflow_err() {
        let orig = [42u8; 32];

        let mut pipe = BufferedPipe::new(16);
        let written = pipe.write_all(&orig);

        assert!(written.is_err());
    }

    #[test]
    fn test_buffered_pipe_underflow_cap() {
        let orig = [42u8; 32];
        let mut piped = [0u8; 64];

        let mut pipe = BufferedPipe::new(256);
        pipe.write_all(&orig).expect("Pipe write failed");
        let read = pipe.read(&mut piped).expect("Pipe read failed");

        assert_eq!(read, 32);
    }

    #[test]
    fn test_buffered_pipe_underflow_err() {
        let orig = [42u8; 32];
        let mut piped = [0u8; 64];

        let mut pipe = BufferedPipe::new(256);
        pipe.write_all(&orig).expect("Pipe write failed");
        let res = pipe.read_exact(&mut piped);

        assert!(res.is_err());
    }
}
