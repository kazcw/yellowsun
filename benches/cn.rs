#![feature(test)]
extern crate test;

use yellowsun::{Algo, AllocPolicy, Hasher};

/*
#[bench]
fn bench_cn1(b: &mut test::Bencher) {
    let mut hasher = Hasher::new(Algo::Cn1);
    let mut hashes = hasher.hashes((&[0u8; 90][..]).to_owned().into_boxed_slice(), 0..);
    b.iter(|| hashes.next())
}
*/

#[bench]
fn bench_cn2(b: &mut test::Bencher) {
    let mut hasher = Hasher::new(Algo::Cn2, AllocPolicy::RequireFast);
    let mut hashes = hasher.hashes((&[0u8; 90][..]).to_owned().into_boxed_slice(), 0..);
    b.iter(|| hashes.next())
}
