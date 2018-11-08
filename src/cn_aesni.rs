// copyright 2017 Kaz Wesley

use std::arch::x86_64::*;
use std::fmt::Debug;

const ITERS: u32 = 0x80000;

#[inline(always)]
fn mul64(x: u64, y: u64) -> (u64, u64) {
    let lo = x.wrapping_mul(y);
    let hi = (u128::from(x).wrapping_mul(u128::from(y)) >> 64) as u64;
    (lo, hi)
}

pub trait Variant: Default + Clone + Debug {
    fn new(blob: &[u8], state: &[u64; 25]) -> Self;
    fn pre_mul(&mut self, b0: u64) -> u64;
    fn int_math(&mut self, _c0: u64, _c1: u64);
    fn post_mul(&mut self, lo: u64, hi: u64) -> __m128i;
    fn end_iter(&mut self, bb: __m128i);
    fn mem_size() -> u32;
    unsafe fn reads(&mut self, mem: &[__m128i], j: u32);
    unsafe fn writes(&self, mem: &mut [__m128i], j: u32, bb: __m128i, aa: __m128i);
}

#[derive(Default, Clone, Debug)]
pub struct Cnv0;

impl Variant for Cnv0 {
    fn new(_blob: &[u8], _state: &[u64; 25]) -> Self {
        Cnv0
    }
    fn pre_mul(&mut self, b0: u64) -> u64 {
        b0
    }
    fn int_math(&mut self, _c0: u64, _c1: u64) {}
    fn post_mul(&mut self, lo: u64, hi: u64) -> __m128i {
        unsafe { _mm_set_epi64x(lo as i64, hi as i64) }
    }
    fn end_iter(&mut self, _bb: __m128i) {}
    fn mem_size() -> u32 {
        0x20_0000
    }
    unsafe fn reads(&mut self, _mem: &[__m128i], _j: u32) {}
    unsafe fn writes(&self, _mem: &mut [__m128i], _j: u32, _bb: __m128i, _aa: __m128i) {}
}

#[derive(Clone, Debug)]
pub struct Cnv2 {
    bb1: __m128i,
    div: u64,
    sqr: u32,
    j1: __m128i,
    j2: __m128i,
    j3: __m128i,
}

impl Default for Cnv2 {
    fn default() -> Self {
        Cnv2 {
            bb1: unsafe { _mm_set_epi64x(0, 0) },
            div: 0,
            sqr: 0,
            j1: unsafe { _mm_set_epi64x(0, 0) },
            j2: unsafe { _mm_set_epi64x(0, 0) },
            j3: unsafe { _mm_set_epi64x(0, 0) },
        }
    }
}

#[inline(always)]
unsafe fn int_sqrt_v2(input: u64) -> u32 {
    let r = {
        let exp_double_bias = _mm_set_epi64x(0, (1023u64 << 52) as i64);
        let x = std::mem::transmute(_mm_add_epi64(
            _mm_cvtsi64_si128((input >> 12) as i64),
            exp_double_bias,
        ));
        let x = _mm_sqrt_sd(_mm_setzero_pd(), x);
        (_mm_cvtsi128_si64(_mm_sub_epi64(std::mem::transmute(x), exp_double_bias)) as u64) >> 19
    };

    let s = r >> 1;
    let b = r & 1;
    let r2 = s.wrapping_mul(s + b).wrapping_add(r << 32);
    (r as u32)
        .wrapping_add((r2.wrapping_add(1 << 32) < input.wrapping_sub(s)) as u32)
        .wrapping_sub((r2.wrapping_add(b) > input) as u32)
}

#[cfg(test)]
#[test]
fn test_int_sqrt() {
    unsafe {
        assert_eq!(int_sqrt_v2(0), 0);
        assert_eq!(int_sqrt_v2(1 << 32), 0);
        assert_eq!(int_sqrt_v2((1 << 32) + 1), 1);
        assert_eq!(int_sqrt_v2(1 << 50), 262140);
        assert_eq!(int_sqrt_v2((1 << 55) + 20963331), 8384515);
        assert_eq!(int_sqrt_v2((1 << 55) + 20963332), 8384516);
        assert_eq!(int_sqrt_v2((1 << 62) + 26599786), 1013904242);
        assert_eq!(int_sqrt_v2((1 << 62) + 26599787), 1013904243);
        assert_eq!(int_sqrt_v2(-1i64 as u64), 3558067407);
    }
}

impl Variant for Cnv2 {
    fn new(_blob: &[u8], state: &[u64; 25]) -> Self {
        let b2 = state[8] ^ state[10];
        let b3 = state[9] ^ state[11];
        let bb1 = unsafe { _mm_set_epi64x(b3 as i64, b2 as i64) };
        let j1 = unsafe { _mm_set_epi64x(0, 0) };
        let j2 = unsafe { _mm_set_epi64x(0, 0) };
        let j3 = unsafe { _mm_set_epi64x(0, 0) };
        let div = state[12];
        let sqr = state[13] as u32;
        Cnv2 {
            bb1,
            div,
            sqr,
            j1,
            j2,
            j3,
        }
    }
    #[inline(always)]
    fn pre_mul(&mut self, b0: u64) -> u64 {
        b0 ^ self.div ^ (u64::from(self.sqr) << 32)
    }
    #[inline(always)]
    fn int_math(&mut self, c0: u64, c1: u64) {
        let dividend: u64 = c1;
        let divisor = ((c0 as u32).wrapping_add(self.sqr << 1)) | 0x8000_0001;
        self.div = u64::from((dividend / u64::from(divisor)) as u32)
            + ((dividend % u64::from(divisor)) << 32);
        self.sqr = unsafe { int_sqrt_v2(c0.wrapping_add(self.div)) };
    }
    #[inline(always)]
    unsafe fn reads(&mut self, mem: &[__m128i], j: u32) {
        self.j1 = *mem.get_unchecked((j ^ 1) as usize);
        self.j2 = *mem.get_unchecked((j ^ 2) as usize);
        self.j3 = *mem.get_unchecked((j ^ 3) as usize);
    }
    #[inline(always)]
    unsafe fn writes(&self, mem: &mut [__m128i], j: u32, bb: __m128i, aa: __m128i) {
        *mem.get_unchecked_mut((j ^ 1) as usize) = _mm_add_epi64(self.j3, self.bb1);
        *mem.get_unchecked_mut((j ^ 2) as usize) = _mm_add_epi64(self.j1, bb);
        *mem.get_unchecked_mut((j ^ 3) as usize) = _mm_add_epi64(self.j2, aa);
    }
    #[inline(always)]
    fn post_mul(&mut self, lo: u64, hi: u64) -> __m128i {
        unsafe {
            let lohi = _mm_set_epi64x(lo as i64, hi as i64);
            self.j1 = _mm_xor_si128(lohi, self.j1);
            _mm_xor_si128(lohi, self.j2)
        }
    }
    #[inline(always)]
    fn end_iter(&mut self, bb: __m128i) {
        self.bb1 = bb;
    }
    #[inline(always)]
    fn mem_size() -> u32 {
        0x20_0000
    }
}

/*
macro_rules! iaca_start {
    () => {
    asm!("mov ebx, 111
             .byte 0x64, 0x67, 0x90" :::: "intel", "volatile");
    }
}

macro_rules! iaca_end {
    () => {
    asm!("mov ebx, 222
             .byte 0x64, 0x67, 0x90" :::: "intel", "volatile");
    }
}
*/

#[inline(always)]
pub(crate) fn mix<V: Variant>(mem: &mut [__m128i], from: &[__m128i], var: V) {
    unsafe {
        assert_eq!(
            V::mem_size() as usize,
            mem.len()
                .checked_mul(std::mem::size_of::<__m128i>())
                .unwrap()
        );
        mix_inner(mem, from, var)
    }
}

#[target_feature(enable = "aes", enable = "sse4.1", enable = "sse4.2")]
unsafe fn mix_inner<V: Variant>(mem: &mut [__m128i], from: &[__m128i], mut var: V) {
    let mut aa = _mm_xor_si128(from[0], from[2]);
    let mut bb = _mm_xor_si128(from[1], from[3]);
    for _ in 0..ITERS {
        let a0 = _mm_extract_epi32(aa, 0) as u32;
        let j = (a0 & (V::mem_size() - 0x10)) >> 4;
        let cc = _mm_aesenc_si128(*mem.get_unchecked(j as usize), aa);
        var.reads(mem, j);
        var.writes(mem, j, bb, aa);
        *mem.get_unchecked_mut(j as usize) = _mm_xor_si128(bb, cc);
        let c0 = _mm_extract_epi64(cc, 0) as u64;
        let c1 = _mm_extract_epi64(cc, 1) as u64;
        let j = ((c0 as u32) & (V::mem_size() - 0x10)) >> 4;
        var.reads(mem, j);
        let b0 = *(mem.get_unchecked(j as usize) as *const _ as *const u64);
        let b1 = *(mem.get_unchecked(j as usize) as *const _ as *const u64).add(1);
        let b0 = var.pre_mul(b0);
        let (lo, hi) = mul64(c0, b0);
        let lohi = var.post_mul(lo, hi);
        var.writes(mem, j, bb, aa);
        aa = _mm_add_epi64(aa, lohi);
        *mem.get_unchecked_mut(j as usize) = aa;
        var.end_iter(bb);
        aa = _mm_xor_si128(aa, _mm_set_epi64x(b1 as i64, b0 as i64));
        bb = cc;
        var.int_math(c0, c1);
    }
}

#[inline(always)]
pub(crate) fn transplode(into: &mut [__m128i], mem: &mut [__m128i], from: &[__m128i]) {
    unsafe {
        assert!(into.len() >= 8);
        assert!(from.len() >= 8);
        transplode_inner(into, mem, from)
    }
}

#[target_feature(enable = "aes")]
unsafe fn transplode_inner(into: &mut [__m128i], mem: &mut [__m128i], from: &[__m128i]) {
    let key_into = genkey(into[2], into[3]);
    let key_from = genkey(from[0], from[1]);
    let into = &mut *(&mut into[4] as *mut _ as *mut [__m128i; 8]);
    let mut from = *(&from[4] as *const _ as *const [__m128i; 8]);
    for m in mem.chunks_exact_mut(8) {
        for (i, m) in into.iter_mut().zip(m.iter()) {
            *i = _mm_xor_si128(*i, *m);
        }
        for k in key_into.iter() {
            for i in into.iter_mut() {
                *i = _mm_aesenc_si128(*i, *k);
            }
        }
        for k in key_from.iter() {
            for f in from.iter_mut() {
                *f = _mm_aesenc_si128(*f, *k);
            }
        }
        for (f, m) in from.iter().zip(m) {
            *m = *f;
        }
    }
}

macro_rules! round_term {
    ($round:expr, $mask:expr, $in:ident) => {{
        _mm_shuffle_epi32(_mm_aeskeygenassist_si128($in, $round), $mask)
    }};
}

#[target_feature(enable = "aes")]
unsafe fn genkey(k0: __m128i, k1: __m128i) -> [__m128i; 10] {
    unsafe fn update_key(xmm0: __m128i, xmm2: __m128i) -> __m128i {
        let xmm3 = _mm_slli_si128(xmm0, 0x4);
        let xmm0 = _mm_xor_si128(xmm0, xmm3);
        let xmm3 = _mm_slli_si128(xmm3, 0x4);
        let xmm0 = _mm_xor_si128(xmm0, xmm3);
        let xmm3 = _mm_slli_si128(xmm3, 0x4);
        let xmm0 = _mm_xor_si128(xmm0, xmm3);
        _mm_xor_si128(xmm0, xmm2)
    }
    let k2 = update_key(k0, round_term!(0x01, 0xFF, k1));
    let k3 = update_key(k1, round_term!(0x00, 0xAA, k2));
    let k4 = update_key(k2, round_term!(0x02, 0xFF, k3));
    let k5 = update_key(k3, round_term!(0x00, 0xAA, k4));
    let k6 = update_key(k4, round_term!(0x04, 0xFF, k5));
    let k7 = update_key(k5, round_term!(0x00, 0xAA, k6));
    let k8 = update_key(k6, round_term!(0x08, 0xFF, k7));
    let k9 = update_key(k7, round_term!(0x00, 0xAA, k8));
    [k0, k1, k2, k3, k4, k5, k6, k7, k8, k9]
}

#[inline(always)]
pub(crate) fn explode(mem: &mut [__m128i], from: &[__m128i]) {
    unsafe {
        assert!(from.len() >= 8);
        explode_inner(mem, from)
    }
}

#[target_feature(enable = "aes")]
unsafe fn explode_inner(mem: &mut [__m128i], from: &[__m128i]) {
    let key_from = genkey(from[0], from[1]);
    let mut from = *(&from[4] as *const _ as *const [__m128i; 8]);
    for m in mem.chunks_exact_mut(8) {
        for k in key_from.iter() {
            for f in from.iter_mut() {
                *f = _mm_aesenc_si128(*f, *k);
            }
        }
        for (f, m) in from.iter().zip(m) {
            *m = *f;
        }
    }
}

#[inline(always)]
pub(crate) fn implode(into: &mut [__m128i], mem: &[__m128i]) {
    unsafe {
        assert!(into.len() >= 8);
        implode_inner(into, mem);
    }
}

#[target_feature(enable = "aes")]
unsafe fn implode_inner(into: &mut [__m128i], mem: &[__m128i]) {
    let key_into = genkey(into[2], into[3]);
    let into = &mut *(&mut into[4] as *mut _ as *mut [__m128i; 8]);
    for m in mem.chunks_exact(8) {
        for (i, m) in into.iter_mut().zip(m.iter()) {
            *i = _mm_xor_si128(*i, *m);
        }
        for k in key_into.iter() {
            for i in into.iter_mut() {
                *i = _mm_aesenc_si128(*i, *k);
            }
        }
    }
}
