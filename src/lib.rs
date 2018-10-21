// copyright 2017 Kaz Wesley

#![feature(chunks_exact)]

#![feature(stdsimd)]

mod cn_aesni;
mod mmap;
mod state;

use blake::digest::Digest;
use skein::digest::generic_array::typenum::U32;
use skein::digest::generic_array::GenericArray;
use std::arch::x86_64::__m128i as i64x2;
use std::str::FromStr;
use byteorder::{ByteOrder, LE};

use self::mmap::Mmap;
use self::state::State;

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

fn set_nonce(blob: &mut [u8], nonce: u32) {
    // XXX XXX XXX
    //LE::write_u32(&mut blob[39..43], nonce);
}

#[derive(Debug)]
pub struct UnknownAlgo{ name: Box<str> }
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Algo {
    Cn0,
    //Cn1,
    Cn2,
}
impl FromStr for Algo {
    type Err = UnknownAlgo;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "cn/0" => Algo::Cn0,
            //"cn/1" => Algo::Cn1,
            "cn/2" => Algo::Cn2,
            name => Err(UnknownAlgo{ name: name.to_owned().into_boxed_str() })?,
        })
    }
}

pub struct Hasher(Hasher_);
enum Hasher_ {
    CryptoNight0{ memory: Mmap<[i64x2; 1 << 17]> },
    //CryptoNight1{ memory: Mmap<[i64x2; 1 << 17]> },
    CryptoNight2{ memory: Mmap<[i64x2; 1 << 17]> },
}
impl Hasher {
    pub fn new(algo: Algo) -> Self {
        Hasher(match algo {
            Algo::Cn0 => Hasher_::CryptoNight0 { memory: Mmap::default() },
            //Algo::Cn1 => Hasher_::CryptoNight1 { memory: Mmap::default() },
            Algo::Cn2 => Hasher_::CryptoNight2 { memory: Mmap::default() },
        })
    }
    pub fn hashes<'a, Noncer: Iterator<Item = u32> + 'static>(&'a mut self, mut blob: Box<[u8]>, noncer: Noncer) -> Hashes<'a> {
        match &mut self.0 {
            Hasher_::CryptoNight0 { memory } => {
                let algo = CryptoNight::<_, cn_aesni::Cnv0>::new(&mut memory[..], noncer, &mut blob);
                Hashes::new(&mut memory[..], blob, Box::new(algo))
            }
            /*
            Hasher_::CryptoNight1 { memory } => {
                let algo = CryptoNight1::new(&mut memory[..], noncer, &mut blob);
                Hashes::new(&mut memory[..], blob, Box::new(algo))
            }*/
            Hasher_::CryptoNight2 { memory } => {
                let algo = CryptoNight::<_, cn_aesni::Cnv2>::new(&mut memory[..], noncer, &mut blob);
                Hashes::new(&mut memory[..], blob, Box::new(algo))
            }
        }
    }
}

pub struct Hashes<'a> {
    memory: &'a mut [i64x2],
    blob: Box<[u8]>,
    algo: Box<dyn Impl>,
}

impl<'a> Hashes<'a> {
    fn new(memory: &'a mut [i64x2], blob: Box<[u8]>, algo: Box<dyn Impl>) -> Self {
        Hashes { memory, blob, algo }
    }
}

impl<'a> Iterator for Hashes<'a> {
    type Item = [u8; 32];
    fn next(&mut self) -> Option<Self::Item> {
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.algo.next_hash(self.memory, &mut self.blob));
        Some(h)
    }
}

trait Impl {
    fn next_hash(&mut self, memory: &mut [i64x2], blob: &mut [u8]) -> GenericArray<u8, U32>;
}

#[derive(Default)]
pub struct CryptoNight<Noncer, Variant> {
    noncer: Noncer,
    state: (State, State),
    variant: Variant,
}
impl<Noncer: Iterator<Item = u32>, Variant: cn_aesni::Variant> CryptoNight<Noncer, Variant> {
    pub fn new(memory: &mut [i64x2], noncer: Noncer, blob: &mut [u8]) -> Self {
        let mut res = Self {
            state: Default::default(),
            variant: Default::default(),
            noncer,
        };
        res.transplode(memory, blob);
        res
    }
    fn transplode(&mut self, memory: &mut [i64x2], blob: &mut [u8]) -> GenericArray<u8, U32> {
        set_nonce(blob, self.noncer.next().unwrap());
        self.state.1 = State::from(sha3::Keccak256Full::digest(blob));
        self.variant = cn_aesni::Variant::new(&blob, (&self.state.1).into());
        cn_aesni::transplode(
            (&mut self.state.0).into(),
            &mut memory[..],
            (&self.state.1).into(),
        );
        let result = finalize(self.state.0);
        self.state.0 = self.state.1;
        result
    }
}
impl<Noncer: Iterator<Item = u32>, Variant: cn_aesni::Variant> Impl for CryptoNight<Noncer, Variant> {
    fn next_hash(&mut self, memory: &mut [i64x2], blob: &mut [u8]) -> GenericArray<u8, U32> {
        cn_aesni::mix(memory, (&self.state.0).into(), self.variant.clone());
        self.transplode(memory, blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::{hex, hex_impl};

    fn test_independent_cases(hasher: &mut Hasher, input: &[&[u8]], output: &[[u8; 32]]) {
        assert_eq!(input.len(), output.len());
        for (&blob, &expected) in input.iter().zip(output) {
            //let nonce = LE::read_u32(&blob[39..43]);
            let nonce = 0;
            let mut hashes = hasher.hashes(blob.to_owned().into_boxed_slice(), nonce..);
            assert_eq!(hashes.next().unwrap(), expected);
        }
    }

    #[test]
    fn test_cn0() {
        // tests-slow.txt
        const IN_V0: &[&[u8]] = &[
            &hex!("6465206f6d6e69627573206475626974616e64756d"),
            &hex!("6162756e64616e732063617574656c61206e6f6e206e6f636574"),
            &hex!("63617665617420656d70746f72"),
            &hex!("6578206e6968696c6f206e6968696c20666974"),
        ];
        const OUT_V0: &[[u8; 32]] = &[
            hex!("2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5"),
            hex!("722fa8ccd594d40e4a41f3822734304c8d5eff7e1b528408e2229da38ba553c4"),
            hex!("bbec2cacf69866a8e740380fe7b818fc78f8571221742d729d9d02d7f8989b87"),
            hex!("b1257de4efc5ce28c6b40ceb1c6c8f812a64634eb3e81c5220bee9b2b76a6f05"),
        ];
        test_independent_cases(&mut Hasher::new(Algo::Cn0), IN_V0, OUT_V0);
    }

    /*
    #[test]
    fn test_cn1() {
        // tests-slow-1.txt
        const IN_V1: &[&[u8]] = &[
            &hex!("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            &hex!("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            &hex!("8519e039172b0d70e5ca7b3383d6b3167315a422747b73f019cf9528f0fde341fd0f2a63030ba6450525cf6de31837669af6f1df8131faf50aaab8d3a7405589"),
            &hex!("37a636d7dafdf259b7287eddca2f58099e98619d2f99bdb8969d7b14498102cc065201c8be90bd777323f449848b215d2977c92c4c1c2da36ab46b2e389689ed97c18fec08cd3b03235c5e4c62a37ad88c7b67932495a71090e85dd4020a9300"),
            &hex!("38274c97c45a172cfc97679870422e3a1ab0784960c60514d816271415c306ee3a3ed1a77e31f6a885c3cb"),
        ];
        const OUT_V1: &[[u8; 32]] = &[
            hex!("b5a7f63abb94d07d1a6445c36c07c7e8327fe61b1647e391b4c7edae5de57a3d"),
            hex!("80563c40ed46575a9e44820d93ee095e2851aa22483fd67837118c6cd951ba61"),
            hex!("5bb40c5880cef2f739bdb6aaaf16161eaae55530e7b10d7ea996b751a299e949"),
            hex!("613e638505ba1fd05f428d5c9f8e08f8165614342dac419adc6a47dce257eb3e"),
            hex!("ed082e49dbd5bbe34a3726a0d1dad981146062b39d36d62c71eb1ed8ab49459b"),
        ];
        test_independent_cases(&mut Hasher::new(Algo::Cn1), IN_V1, OUT_V1);
    }
    */

    #[test]
    fn test_cn2() {
        // tests-slow-2.txt
        const IN_V2: &[&[u8]] = &[
            &hex!("5468697320697320612074657374205468697320697320612074657374205468697320697320612074657374"),
            &hex!("4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e67"),
            &hex!("656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f7265"),
            &hex!("657420646f6c6f7265206d61676e6120616c697175612e20557420656e696d206164206d696e696d2076656e69616d2c"),
            &hex!("71756973206e6f737472756420657865726369746174696f6e20756c6c616d636f206c61626f726973206e697369"),
            &hex!("757420616c697175697020657820656120636f6d6d6f646f20636f6e7365717561742e20447569732061757465"),
            &hex!("697275726520646f6c6f7220696e20726570726568656e646572697420696e20766f6c7570746174652076656c6974"),
            &hex!("657373652063696c6c756d20646f6c6f726520657520667567696174206e756c6c612070617269617475722e"),
            &hex!("4578636570746575722073696e74206f6363616563617420637570696461746174206e6f6e2070726f6964656e742c"),
            &hex!("73756e7420696e2063756c706120717569206f666669636961206465736572756e74206d6f6c6c697420616e696d20696420657374206c61626f72756d2e"),
        ];
        const OUT_V2: &[[u8; 32]] = &[
            hex!("353fdc068fd47b03c04b9431e005e00b68c2168a3cc7335c8b9b308156591a4f"),
            hex!("72f134fc50880c330fe65a2cb7896d59b2e708a0221c6a9da3f69b3a702d8682"),
            hex!("410919660ec540fc49d8695ff01f974226a2a28dbbac82949c12f541b9a62d2f"),
            hex!("4472fecfeb371e8b7942ce0378c0ba5e6d0c6361b669c587807365c787ae652d"),
            hex!("577568395203f1f1225f2982b637f7d5e61b47a0f546ba16d46020b471b74076"),
            hex!("f6fd7efe95a5c6c4bb46d9b429e3faf65b1ce439e116742d42b928e61de52385"),
            hex!("422f8cfe8060cf6c3d9fd66f68e3c9977adb683aea2788029308bbe9bc50d728"),
            hex!("512e62c8c8c833cfbd9d361442cb00d63c0a3fd8964cfd2fedc17c7c25ec2d4b"),
            hex!("12a794c1aa13d561c9c6111cee631ca9d0a321718d67d3416add9de1693ba41e"),
            hex!("2659ff95fc74b6215c1dc741e85b7a9710101b30620212f80eb59c3c55993f9d"),
        ];
        test_independent_cases(&mut Hasher::new(Algo::Cn2), IN_V2, OUT_V2);
    }
}
