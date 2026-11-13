//! Hostile-input smoke tests: random and mutated bytes must produce errors, never panics.
//! A seeded generator keeps failures reproducible; for deeper runs raise `ROUNDS`.

use mtg_mtproto::mtp::{Encrypted, Mtp, Plain};
use mtg_mtproto::transport::{Abridged, Full, Intermediate, Obfuscated, Transport};

const ROUNDS: usize = 20_000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// Random bytes; lengths are biased to small values and to multiples of 4 and 16, where
    /// parsers have their boundaries.
    fn bytes(&mut self) -> Vec<u8> {
        let len = match self.below(4) {
            0 => self.below(32),
            1 => self.below(32) * 4,
            2 => self.below(70) * 16,
            _ => self.below(1500),
        };
        (0..len).map(|_| self.next() as u8).collect()
    }
}

fn transports() -> Vec<Box<dyn Transport>> {
    vec![
        Box::new(Abridged::new()),
        Box::new(Intermediate::new()),
        Box::new(Full::new()),
        Box::new(Obfuscated::new(Abridged::new())),
        Box::new(Obfuscated::new(Intermediate::new())),
    ]
}

#[test]
fn transports_survive_garbage() {
    let mut rng = Rng(1);
    for _ in 0..ROUNDS / 10 {
        let data = rng.bytes();
        for mut t in transports() {
            // the way `connection` feeds a transport: a growing prefix of the same stream
            let mut buf = data.clone();
            for end in (0..=buf.len()).step_by(7) {
                let _ = t.unpack(&mut buf[..end]);
            }
            let _ = t.unpack(&mut buf);
        }
    }
}

#[test]
fn transports_survive_mutated_tags_and_lengths() {
    let mut rng = Rng(2);
    for _ in 0..ROUNDS {
        // a header-ish prefix with extreme values, then noise
        let mut data = vec![
            [0x7f, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00][rng.below(8)],
            [0x00, 0x01, 0x7f, 0x80, 0xff][rng.below(5)],
            0xff,
            0xff,
        ];
        data.extend(rng.bytes());
        for mut t in transports() {
            let mut buf = data.clone();
            let _ = t.unpack(&mut buf);
        }
    }
}

#[test]
fn encrypted_deserialize_survives_garbage() {
    let mut rng = Rng(3);
    let mut m = Encrypted::build().finish([7; 256]);
    let key_id = mtg_crypto::AuthKey::from_bytes([7; 256]).key_id();
    for _ in 0..ROUNDS {
        let mut data = rng.bytes();
        let _ = m.deserialize(&mut data);
        // right auth key id (the first 8 bytes), wrong everything else
        let mut data = rng.bytes();
        if data.len() >= 8 {
            data[..8].copy_from_slice(&key_id);
        }
        let _ = m.deserialize(&mut data);
    }
}

#[test]
fn plain_deserialize_survives_garbage() {
    let mut rng = Rng(4);
    let mut m = Plain::new();
    for _ in 0..ROUNDS {
        let mut data = rng.bytes();
        let _ = m.deserialize(&mut data);
    }
}

#[test]
fn unpacked_offsets_stay_inside_the_buffer() {
    let mut rng = Rng(6);
    for _ in 0..ROUNDS {
        let data = rng.bytes();
        for (name, mut t) in [
            ("abridged", Box::new(Abridged::new()) as Box<dyn Transport>),
            ("intermediate", Box::new(Intermediate::new())),
            ("full", Box::new(Full::new())),
        ] {
            let mut buf = data.clone();
            if let Ok(o) = t.unpack(&mut buf) {
                assert!(
                    o.next_offset <= buf.len(),
                    "{name}: {o:?} for {}",
                    buf.len()
                );
                assert!(o.data_range.end <= o.next_offset, "{name}: {o:?}");
            }
        }
    }
}

#[test]
fn known_bad_headers_are_errors() {
    use mtg_mtproto::transport::Error;

    // abridged: 4-byte header whose 24-bit length has the top bit set (was negative)
    let mut b = [0x7f, 0xff, 0xff, 0xff, 0, 0, 0, 0];
    assert!(matches!(
        Abridged::new().unpack(&mut b),
        Err(Error::MissingBytes)
    ));
    // intermediate: length 4 announces an 8-byte status packet but only the header arrived
    let mut b = 4i32.to_le_bytes();
    assert!(matches!(
        Intermediate::new().unpack(&mut b),
        Err(Error::MissingBytes)
    ));
    // intermediate: a length that is past the buffer (the check forgot the header)
    let mut b = [8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
    assert!(Intermediate::new().unpack(&mut b[..8]).is_err());
    assert!(Intermediate::new().unpack(&mut b).is_ok());
    // intermediate and full: negative and i32::MIN lengths
    for len in [-1i32, i32::MIN] {
        let mut b = len.to_le_bytes();
        assert!(Intermediate::new().unpack(&mut b).is_err());
        let mut b = len.to_le_bytes();
        assert!(matches!(
            Full::new().unpack(&mut b),
            Err(Error::BadStatus { .. })
        ));
    }
}
