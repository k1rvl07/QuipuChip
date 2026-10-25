//! Randomness abstraction.
//!
//! `pm-core` never reaches for a global RNG: the board provides entropy
//! (`esp_fill_random`), while tests inject a deterministic source. This mirrors
//! the swappable `g_randSrc` in the C++ reference.

/// A source of uniformly random bytes.
pub trait RandomSource {
    /// Fills `buf` completely.
    fn fill(&mut self, buf: &mut [u8]);
}

/// Deterministic source that replays a byte slice cyclically.
///
/// Reproduces the C++ test harness behaviour: one charge is one call, and the
/// cursor wraps around the buffer, so a short buffer (e.g. all `0xFF`) is read
/// over and over.
pub struct CycleSource<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CycleSource<'a> {
    /// Creates a source replaying `data` cyclically.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl RandomSource for CycleSource<'_> {
    fn fill(&mut self, buf: &mut [u8]) {
        assert!(
            !self.data.is_empty(),
            "CycleSource needs a non-empty buffer"
        );
        for b in buf.iter_mut() {
            *b = self.data[self.pos];
            self.pos = (self.pos + 1) % self.data.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycle_source_wraps() {
        let mut s = CycleSource::new(&[1, 2, 3]);
        let mut buf = [0u8; 7];
        s.fill(&mut buf);
        assert_eq!(buf, [1, 2, 3, 1, 2, 3, 1]);
    }

    #[test]
    fn cycle_source_keeps_its_position_across_fills() {
        let mut s = CycleSource::new(&[1, 2, 3]);
        let mut a = [0u8; 2];
        s.fill(&mut a);
        assert_eq!(a, [1, 2]);
        let mut b = [0u8; 2];
        s.fill(&mut b);
        assert_eq!(b, [3, 1]);
    }

    #[test]
    #[should_panic(expected = "non-empty")]
    fn cycle_source_refuses_an_empty_buffer() {
        // An empty source would divide by zero in the wrap-around; the panic
        // is a test-harness bug, not a device condition.
        let mut s = CycleSource::new(&[]);
        let mut buf = [0u8; 1];
        s.fill(&mut buf);
    }
}
