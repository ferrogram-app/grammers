//! Random bytes must not panic or allocate absurd amounts in the TL deserializer.

use mtg_tl_types::{Deserializable, enums};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

/// Constructor ids of big recursive types, so random tails reach deep parsing paths.
const SEEDS: [u32; 6] = [
    0x74ae4240, // updates
    0x313bc7f8, // updateShort
    0x2b0f5a8b, // updatesCombined-ish
    0x9015e101, // messages.messages-ish
    0x5bb8e511, // message-ish
    0x1c9b1027, // junk
];

fn run<T: Deserializable>(rng: &mut Rng, rounds: usize) {
    for _ in 0..rounds {
        let len = (rng.next() % 600) as usize;
        let mut data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        if data.len() >= 4 && rng.next().is_multiple_of(2) {
            let id = SEEDS[(rng.next() % SEEDS.len() as u64) as usize];
            data[..4].copy_from_slice(&id.to_le_bytes());
        }
        // huge vector counts right after the constructor id
        if data.len() >= 12 && rng.next().is_multiple_of(3) {
            data[8..12].copy_from_slice(&[0xff, 0xff, 0xff, 0x7f]);
        }
        let _ = T::from_bytes(&data);
    }
}

#[test]
fn deserializers_survive_garbage() {
    let mut rng = Rng(11);
    run::<enums::Updates>(&mut rng, 20_000);
    run::<enums::Message>(&mut rng, 20_000);
    run::<enums::messages::Messages>(&mut rng, 20_000);
    run::<enums::updates::Difference>(&mut rng, 20_000);
    run::<enums::User>(&mut rng, 20_000);
    run::<enums::Chat>(&mut rng, 20_000);
    run::<enums::Config>(&mut rng, 20_000);
    run::<enums::MessageEntity>(&mut rng, 20_000);
    run::<Vec<enums::Message>>(&mut rng, 20_000);
    run::<Vec<i64>>(&mut rng, 20_000);
}
