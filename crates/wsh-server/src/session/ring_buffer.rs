//! Circular buffer for stream replay on session reattach.
//!
//! Stores the last N bytes of PTY output so that a reconnecting client
//! can receive a scrollback snapshot without the server keeping unbounded history.

/// A fixed-capacity circular byte buffer.
#[derive(Debug)]
pub struct RingBuffer {
    buf: Vec<u8>,
    capacity: usize,
    /// Write position (wraps around).
    write_pos: usize,
    /// Total bytes ever written (used to detect wrap).
    total_written: u64,
}

impl RingBuffer {
    /// Create a new ring buffer with the given capacity in bytes.
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: vec![0u8; capacity],
            capacity,
            write_pos: 0,
            total_written: 0,
        }
    }

    /// Write data into the ring buffer, overwriting oldest data if full.
    pub fn write(&mut self, data: &[u8]) {
        if self.capacity == 0 {
            return;
        }

        for &byte in data {
            self.buf[self.write_pos] = byte;
            self.write_pos = (self.write_pos + 1) % self.capacity;
            self.total_written += 1;
        }
    }

    /// Read all buffered data in chronological order.
    ///
    /// Returns up to `capacity` bytes, starting from the oldest data.
    pub fn read_all(&self) -> Vec<u8> {
        if self.total_written == 0 {
            return Vec::new();
        }

        let len = self.len();
        let mut result = Vec::with_capacity(len);

        if self.total_written <= self.capacity as u64 {
            // Haven't wrapped yet — data starts at 0
            result.extend_from_slice(&self.buf[..len]);
        } else {
            // Wrapped — oldest data starts at write_pos
            result.extend_from_slice(&self.buf[self.write_pos..]);
            result.extend_from_slice(&self.buf[..self.write_pos]);
        }

        result
    }

    /// Number of valid bytes currently stored.
    pub fn len(&self) -> usize {
        if self.total_written >= self.capacity as u64 {
            self.capacity
        } else {
            self.total_written as usize
        }
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.total_written == 0
    }

    /// Total bytes ever written through this buffer.
    pub fn total_written(&self) -> u64 {
        self.total_written
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.write_pos = 0;
        self.total_written = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_write_read() {
        let mut rb = RingBuffer::new(10);
        rb.write(b"hello");
        assert_eq!(rb.read_all(), b"hello");
        assert_eq!(rb.len(), 5);
    }

    #[test]
    fn wrap_around() {
        let mut rb = RingBuffer::new(5);
        rb.write(b"abcde"); // fills exactly
        rb.write(b"fg"); // overwrites a, b
        assert_eq!(rb.read_all(), b"cdefg");
        assert_eq!(rb.len(), 5);
    }

    #[test]
    fn empty_buffer() {
        let rb = RingBuffer::new(10);
        assert!(rb.is_empty());
        assert_eq!(rb.read_all(), Vec::<u8>::new());
    }

    #[test]
    fn zero_capacity() {
        let mut rb = RingBuffer::new(0);
        rb.write(b"test");
        assert!(rb.is_empty());
    }
}
