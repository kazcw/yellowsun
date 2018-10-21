// copyright 2017 Kaz Wesley

use std::arch::x86_64::*;

pub fn mix(memory: &mut [__m128i], from: &[__m128i], tweak: u64) {
    unsafe {
        mix_inner(memory, from, tweak);
    }
}

const ITERS: u32 = 0x80000;

fn mul64(x: u64, y: u64) -> (u64, u64) {
    let lo = x.wrapping_mul(y);
    let hi = (u128::from(x).wrapping_mul(u128::from(y)) >> 64) as u64;
    (lo, hi)
}

struct Cnv1 {
    x5: __m128i,
    x7: __m128i,
}

impl Cnv1 {
    #[target_feature(enable = "aes", enable = "sse4.1", enable = "sse4.2")]
    unsafe fn new(tweak: u64) -> Cnv1 {
        let x1 = _mm_set_epi64x(0, 0);
        let x5 = _mm_insert_epi64(_mm_xor_si128(x1, x1), tweak as i64, 1);
        let x7 = _mm_insert_epi8(_mm_xor_si128(x1, x1), 0x10, 11);
        Cnv1 { x5, x7 }
    }
    #[target_feature(enable = "aes", enable = "sse4.1", enable = "sse4.2")]
    unsafe fn tweak1(&self, mut x2: __m128i) -> __m128i {
        let mut x6 = x2;
        let x3 = _mm_and_si128(self.x7, x2);
        x2 = _mm_slli_epi32(x2, 4);
        let x4 = _mm_and_si128(self.x7, x2);
        x2 = _mm_andnot_si128(x2, x3);
        x2 = _mm_add_epi64(x2, x2);
        x2 = _mm_xor_si128(x2, x6);
        x6 = _mm_srli_epi32(x6, 1);
        x6 = _mm_andnot_si128(x6, x4);
        x6 = _mm_xor_si128(x6, self.x7);
        _mm_xor_si128(x2, x6)
    }
    unsafe fn tweak2(&self, x4: __m128i) -> __m128i {
        _mm_xor_si128(x4, self.x5)
    }
    const fn mem_size() -> u32 {
        0x20_0000
    }
}

#[target_feature(enable = "aes", enable = "sse4.1", enable = "sse4.2")]
unsafe fn mix_inner(mem: &mut [__m128i], from: &[__m128i], tweak: u64) {
    let mut x1 = _mm_xor_si128(from[0], from[2]);
    let mut x2 = _mm_xor_si128(from[1], from[3]);
    let mut r8 = _mm_extract_epi64(x1, 0) as u32;
    let var = Cnv1::new(tweak);
    for _ in 0..ITERS {
        let bx = r8 & (Cnv1::mem_size() - 0x10);
        let x0 = *mem.get_unchecked((bx >> 4) as usize);
        let x0 = _mm_aesenc_si128(x0, x1);
        x2 = _mm_xor_si128(x2, x0);
        *mem.get_unchecked_mut((bx >> 4) as usize) = var.tweak1(x2);
        let ax = _mm_extract_epi64(x0, 0) as u64;
        let si = (ax as u32) & (Cnv1::mem_size() - 0x10);
        let x4 = var.tweak2(*mem.get_unchecked((si >> 4) as usize));
        let r9 = _mm_extract_epi64(x4, 0) as u64;
        let (ax, dx) = mul64(ax, r9);
        r8 = r8.wrapping_add(dx as u32) ^ r9 as u32;
        x1 = _mm_add_epi64(x1, _mm_set_epi64x(ax as i64, dx as i64));
        x1 = var.tweak2(x1);
        *mem.get_unchecked_mut((si >> 4) as usize) = x1;
        x1 = _mm_xor_si128(x1, x4);
        x2 = x0;
    }
}

pub(crate) fn transplode(into: &mut [__m128i], mem: &mut [__m128i], from: &[__m128i]) {
    unsafe { transplode_inner(into, mem, from); }
}

#[target_feature(enable = "aes")]
unsafe fn transplode_inner(into: &mut [__m128i], mem: &mut [__m128i], from: &[__m128i]) {
    let key_into = genkey(into[2], into[3]);
    let key_from = genkey(from[0], from[1]);
    let into = &mut *(&mut into[4] as *mut _ as *mut [__m128i; 8]);
    let mut from = *(&from[4] as *const _ as *const [__m128i; 8]);
    for m in mem.chunks_exact_mut(8) {
        for (i, m) in into.iter_mut().zip(m.iter()) { *i = _mm_xor_si128(*i, *m); }
        for k in key_into.iter() {
            for i in into.iter_mut() { *i = _mm_aesenc_si128(*i, *k); }
        }
        for k in key_from.iter() {
            for f in from.iter_mut() { *f = _mm_aesenc_si128(*f, *k); }
        }
        for (f, m) in from.iter().zip(m) { *m = *f; }
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
