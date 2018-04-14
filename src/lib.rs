// copyright 2017 Kaz Wesley

#![feature(asm)]
#![feature(attr_literals)]
#![feature(ptr_internals)]
#![feature(repr_simd)]
#![feature(stdsimd)]
#![feature(type_ascription)]
#![feature(unique)]
#![feature(untagged_unions)]
#![cfg_attr(test, feature(plugin))]
#![cfg_attr(test, plugin(hex_literals))]

extern crate blake;
extern crate groestl_aesni;
extern crate jh_x86_64;
extern crate keccak;
extern crate libc;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate sha3;
extern crate skein;

mod aesni;
mod cn_aesni;
mod mmap;
mod state;

use blake::digest::Digest;
use mmap::Mmap;
use skein::digest::generic_array::typenum::U32;
use skein::digest::generic_array::GenericArray;
use state::State;
use std::simd::i64x2;

fn finalize(mut data: State) -> GenericArray<u8, U32> {
    keccak::f1600((&mut data).into());
    let bytes: &[u8; 200] = (&data).into();
    match bytes[0] & 3 {
        0 => blake::Blake256::digest(bytes),
        1 => groestl_aesni::Groestl256::digest(bytes),
        2 => jh_x86_64::Jh256::digest(bytes),
        3 => skein::Skein512::<U32>::digest(bytes),
        _ => unreachable!(),
    }
}

fn read_u64le(bytes: &[u8]) -> u64 {
    (bytes[0] as u64) | ((bytes[1] as u64) << 8) | ((bytes[2] as u64) << 16)
        | ((bytes[3] as u64) << 24) | ((bytes[4] as u64) << 32) | ((bytes[5] as u64) << 40)
        | ((bytes[6] as u64) << 48) | ((bytes[7] as u64) << 56)
}

fn set_nonce(blob: &mut [u8], nonce: u32) {
    blob[39] = (nonce >> 0x18) as u8;
    blob[40] = (nonce >> 0x10) as u8;
    blob[41] = (nonce >> 0x08) as u8;
    blob[42] = (nonce >> 0x00) as u8;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum HasherConfig {
    #[serde(rename = "cn7-aesni-x1")]
    Cn7AesniX1,
    #[serde(rename = "cnl-aesni-x1")]
    CnLAesniX1,
    #[serde(rename = "cnl-aesni-x2")]
    CnLAesniX2,
}

pub trait Hasher<Noncer> {
    fn set_blob(&mut self, blob: Vec<u8>, noncer: Noncer);
    fn next_hash(&mut self) -> GenericArray<u8, U32>;
}

impl<Noncer> Iterator for Hasher<Noncer> {
    type Item = GenericArray<u8, U32>;
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_hash())
    }
}

pub fn hasher<Noncer: Iterator<Item = u32> + 'static>(
    cfg: HasherConfig,
    blob: Vec<u8>,
    noncer: Noncer,
) -> Box<Hasher<Noncer>> {
    match cfg {
        HasherConfig::Cn7AesniX1 => Box::new(CryptoNight::new(blob, noncer)),
        HasherConfig::CnLAesniX1 => Box::new(CryptoNightLite::new(blob, noncer)),
        HasherConfig::CnLAesniX2 => Box::new(CryptoNightLite2::new(blob, noncer)),
    }
}

#[derive(Default)]
pub struct CryptoNight<Noncer> {
    memory: Mmap<[i64x2; 1 << 17]>,
    blob: Vec<u8>,
    state0: State,
    state1: State,
    tweak: u64,
    noncer: Noncer,
}

impl<Noncer: Iterator<Item = u32>> CryptoNight<Noncer> {
    fn transplode(&mut self) -> GenericArray<u8, U32> {
        set_nonce(&mut self.blob, self.noncer.next().unwrap());
        self.state1 = State::from(sha3::Keccak256Full::digest(&self.blob));
        self.tweak = read_u64le(&self.blob[35..43]) ^ ((&self.state1).into(): &[u64; 25])[24];
        cn_aesni::transplode(
            (&mut self.state0).into(),
            &mut self.memory[..],
            (&self.state1).into(),
        );
        let result = finalize(self.state0);
        self.state0 = self.state1;
        result
    }

    fn mix(&mut self) {
        cn_aesni::mix(&mut self.memory, (&self.state0).into(), self.tweak);
    }
}

impl<Noncer: Iterator<Item = u32>> CryptoNight<Noncer> {
    pub fn new(blob: Vec<u8>, noncer: Noncer) -> Self {
        let mut res = Self {
            memory: Default::default(),
            blob,
            state0: Default::default(),
            state1: Default::default(),
            tweak: Default::default(),
            noncer,
        };
        res.transplode();
        res
    }
}

impl<Noncer: Iterator<Item = u32>> Hasher<Noncer> for CryptoNight<Noncer> {
    fn set_blob(&mut self, blob: Vec<u8>, noncer: Noncer) {
        self.blob = blob;
        self.noncer = noncer;
        self.transplode();
    }

    fn next_hash(&mut self) -> GenericArray<u8, U32> {
        self.mix();
        self.transplode()
    }
}

#[derive(Default)]
pub struct CryptoNightLite<Noncer> {
    memory: Mmap<[i64x2; 1 << 16]>,
    blob: Vec<u8>,
    state0: State,
    state1: State,
    noncer: Noncer,
}

impl<Noncer: Iterator<Item = u32>> CryptoNightLite<Noncer> {
    fn transplode(&mut self) -> GenericArray<u8, U32> {
        set_nonce(&mut self.blob, self.noncer.next().unwrap());
        self.state1 = State::from(sha3::Keccak256Full::digest(&self.blob));
        cn_aesni::transplode(
            (&mut self.state0).into(),
            &mut self.memory[..],
            (&self.state1).into(),
        );
        let result = finalize(self.state0);
        self.state0 = self.state1;
        result
    }

    fn mix(&mut self) {
        cn_aesni::mix_lite(&mut self.memory, (&self.state0).into());
    }
}

impl<Noncer: Iterator<Item = u32>> CryptoNightLite<Noncer> {
    pub fn new(blob: Vec<u8>, noncer: Noncer) -> Self {
        let mut res = Self {
            memory: Default::default(),
            blob,
            state0: Default::default(),
            state1: Default::default(),
            noncer,
        };
        res.transplode();
        res
    }
}

impl<Noncer: Iterator<Item = u32>> Hasher<Noncer> for CryptoNightLite<Noncer> {
    fn set_blob(&mut self, blob: Vec<u8>, noncer: Noncer) {
        self.blob = blob;
        self.noncer = noncer;
        self.transplode();
    }

    fn next_hash(&mut self) -> GenericArray<u8, U32> {
        self.mix();
        self.transplode()
    }
}

#[derive(Default)]
pub struct CryptoNightLite2<Noncer> {
    memory: Mmap<[[i64x2; 1 << 16]; 2]>,
    state: [(State, State); 2],
    blob: Vec<u8>,
    noncer: Noncer,
    result: Option<GenericArray<u8, U32>>,
}

impl<Noncer: Iterator<Item = u32>> CryptoNightLite2<Noncer> {
    pub fn new(blob: Vec<u8>, noncer: Noncer) -> Self {
        let mut res = Self {
            memory: Default::default(),
            state: Default::default(),
            result: Default::default(),
            blob,
            noncer,
        };
        res.transplode();
        res
    }

    fn transplode(&mut self) -> [GenericArray<u8, U32>; 2] {
        for st in &mut self.state {
            set_nonce(&mut self.blob, self.noncer.next().unwrap());
            st.1 = State::from(sha3::Keccak256Full::digest(&self.blob));
        }
        for (st, mem) in self.state.iter_mut().zip(self.memory.iter_mut()) {
            cn_aesni::transplode((&mut st.0).into(), &mut mem[..], (&st.1).into());
        }
        let result = [finalize(self.state[0].0), finalize(self.state[1].0)];
        for st in &mut self.state {
            st.0 = st.1;
        }
        result
    }

    fn mix(&mut self) {
        cn_aesni::mix_lite_x2(
            &mut self.memory,
            (&self.state[0].0).into(),
            (&self.state[1].0).into(),
        );
    }
}

impl<Noncer: Iterator<Item = u32>> Hasher<Noncer> for CryptoNightLite2<Noncer> {
    fn set_blob(&mut self, blob: Vec<u8>, noncer: Noncer) {
        self.blob = blob;
        self.noncer = noncer;
        self.transplode();
    }

    fn next_hash(&mut self) -> GenericArray<u8, U32> {
        if let Some(res) = self.result {
            self.result = None;
            return res;
        }
        self.mix();
        let res = self.transplode();
        self.result = Some(res[1]);
        res[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // "official" slow_hash test vectors, from tests-slow-1.txt
    const INPUT0: &[u8] = hex!(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    const INPUT1: &[u8] = hex!("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    const INPUT2: &[u8] = hex!("8519e039172b0d70e5ca7b3383d6b3167315a422747b73f019cf9528f0fde341fd0f2a63030ba6450525cf6de31837669af6f1df8131faf50aaab8d3a7405589");
    const INPUT3: &[u8] = hex!("37a636d7dafdf259b7287eddca2f58099e98619d2f99bdb8969d7b14498102cc065201c8be90bd777323f449848b215d2977c92c4c1c2da36ab46b2e389689ed97c18fec08cd3b03235c5e4c62a37ad88c7b67932495a71090e85dd4020a9300");
    const INPUT4: &[u8] = hex!(
        "38274c97c45a172cfc97679870422e3a1ab0784960c60514d816271415c306ee3a3ed1a77e31f6a885c3cb"
    );
    const OUTPUT0: &[u8] = hex!("b5a7f63abb94d07d1a6445c36c07c7e8327fe61b1647e391b4c7edae5de57a3d");
    const OUTPUT1: &[u8] = hex!("80563c40ed46575a9e44820d93ee095e2851aa22483fd67837118c6cd951ba61");
    const OUTPUT2: &[u8] = hex!("5bb40c5880cef2f739bdb6aaaf16161eaae55530e7b10d7ea996b751a299e949");
    const OUTPUT3: &[u8] = hex!("613e638505ba1fd05f428d5c9f8e08f8165614342dac419adc6a47dce257eb3e");
    const OUTPUT4: &[u8] = hex!("ed082e49dbd5bbe34a3726a0d1dad981146062b39d36d62c71eb1ed8ab49459b");
    const LITEOU0: &[u8] = hex!("f2360d43b1c6c343e9f53da17e213a51325b05e7909ae9405f828ee45b8282f4");
    const LITEOU1: &[u8] = hex!("4c3428f39e1f9ecda3b0726fd4f4fca62843597c480f033ae38d113282b273bf");
    const LITEOU2: &[u8] = hex!("f828ff6bf19a6e72a77319808e43f745f90f47eceb698e4319d2484404b081e8");
    const LITEOU3: &[u8] = hex!("61e3cb5e046ae4ac5d03f8ec6bd7a9a80d5e2573817429d1624735f66aff4b11");
    const LITEOU4: &[u8] = hex!("12c2f26b89cc514707ac0fb953f1f72581eb468de2a5d4d4cf95c0d1b32f7285");

    fn test_cn(input: &[u8], output: &[u8], nonce: u32) {
        assert_eq!(
            &((&mut CryptoNight::new(input.iter().cloned().collect(), nonce..) as &mut Hasher<_>)
                .next_hash())[..],
            output
        );
    }

    fn test_cnl(input: &[u8], output: &[u8], nonce: u32) {
        assert_eq!(
            &((&mut CryptoNightLite::new(input.iter().cloned().collect(), nonce..)
                as &mut Hasher<_>)
                .next_hash())[..],
            output
        );
    }

    fn test_cnl_x2(input: &[u8], output: &[u8], nonce: u32) {
        assert_eq!(
            &((&mut CryptoNightLite2::new(input.iter().cloned().collect(), nonce..)
                as &mut Hasher<_>)
                .next_hash())[..],
            output
        );
    }

    #[test]
    fn test_cn_0() {
        test_cn(INPUT0, OUTPUT0, 0);
    }

    #[test]
    fn test_cn_1() {
        test_cn(INPUT1, OUTPUT1, 0);
    }

    #[test]
    fn test_cn_2() {
        test_cn(INPUT2, OUTPUT2, 0x450525cf);
    }

    #[test]
    fn test_cn_3() {
        test_cn(INPUT3, OUTPUT3, 0x777323f4);
    }

    #[test]
    fn test_cn_4() {
        test_cn(INPUT4, OUTPUT4, 0xa885c3cb);
    }

    #[test]
    fn test_cnl_0() {
        test_cnl(INPUT0, LITEOU0, 0);
    }

    #[test]
    fn test_cnl_1() {
        test_cnl(INPUT1, LITEOU1, 0);
    }

    #[test]
    fn test_cnl_2() {
        test_cnl(INPUT2, LITEOU2, 0x450525cf);
    }

    #[test]
    fn test_cnl_3() {
        test_cnl(INPUT3, LITEOU3, 0x777323f4);
    }

    #[test]
    fn test_cnl_4() {
        test_cnl(INPUT4, LITEOU4, 0xa885c3cb);
    }

    #[test]
    fn test_cnl_x2_0() {
        test_cnl_x2(INPUT0, LITEOU0, 0);
    }

    #[test]
    fn test_cnl_x2_1() {
        test_cnl_x2(INPUT1, LITEOU1, 0);
    }

    #[test]
    fn test_cnl_x2_2() {
        test_cnl_x2(INPUT2, LITEOU2, 0x450525cf);
    }

    #[test]
    fn test_cnl_x2_3() {
        test_cnl_x2(INPUT3, LITEOU3, 0x777323f4);
    }

    #[test]
    fn test_cnl_x2_4() {
        test_cnl_x2(INPUT4, LITEOU4, 0xa885c3cb);
    }

    #[test]
    fn test_cnl_cnl_x2() {
        for (cnl, cnlx2) in (&mut CryptoNightLite::new(INPUT3.iter().cloned().collect(), 0..)
            as &mut Hasher<_>)
            .zip(
                &mut CryptoNightLite2::new(INPUT3.iter().cloned().collect(), 0..) as &mut Hasher<_>,
            )
            .take(5)
        {
            assert_eq!(cnlx2, cnl);
        }
    }
}
