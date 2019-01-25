use yellowsun::{Algo, AllocPolicy, Hasher};

fn main() {
    let start = std::time::Instant::now();
    let limit: u32 = std::env::args()
        .skip(1)
        .next()
        .map(|x| x.parse().unwrap())
        .unwrap_or(std::u32::MAX);
    let mut hasher = Hasher::new(Algo::Cn2, AllocPolicy::RequireFast);
    let mut hashes = hasher.hashes((&[0u8; 90][..]).to_owned().into_boxed_slice(), 0..);
    for _ in 0..limit {
        hashes.next();
    }
    eprintln!("count: {}", limit);
    eprintln!(
        "time: {} s",
        start.elapsed().as_nanos() as f64 / 1_000_000_000 as f64
    );
    eprintln!(
        "rate: {} H/s",
        limit as f64 * 1_000_000_000.0 / start.elapsed().as_nanos() as f64
    );
}
