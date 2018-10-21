// copyright 2017 Kaz Wesley

use std::arch::x86_64::*;
use std::fmt::Debug;

pub fn mix<V: Variant>(memory: &mut [__m128i], from: &[__m128i], variant: V) {
    unsafe {
        mix_inner(memory, from, variant);
    }
}

const ITERS: u32 = 0x80000;

fn mul64(x: u64, y: u64) -> (u64, u64) {
    let lo = x.wrapping_mul(y);
    let hi = (u128::from(x).wrapping_mul(u128::from(y)) >> 64) as u64;
    (lo, hi)
}

pub trait Variant: Default + Clone + Debug {
    fn new(blob: &[u8], state: &[u64; 25]) -> Self;
    fn shuffle_add(&mut self, mem: &mut [__m128i], j: u32, bb: __m128i, aa: __m128i);
    fn pre_mul(&mut self, b0: u64, c0: u64, c1: u64) -> u64;
    unsafe fn post_mul(&mut self, mem: *mut u64, j: u32, lo: u64, hi: u64) -> (u64, u64);
    fn end_iter(&mut self, bb: __m128i);
    fn mem_size() -> u32;
}

#[derive(Default, Clone, Debug)]
pub struct Cnv0;

impl Variant for Cnv0 {
    fn new(_blob: &[u8], _state: &[u64; 25]) -> Self { Cnv0 }
    fn shuffle_add(&mut self, _mem: &mut [__m128i], _j: u32, _bb: __m128i, _aa: __m128i) {}
    fn pre_mul(&mut self, b0: u64, _c0: u64, _c1: u64) -> u64 { b0 }
    unsafe fn post_mul(&mut self, _mem: *mut u64, _j: u32, lo: u64, hi: u64) -> (u64, u64) { (lo, hi) }
    fn end_iter(&mut self, _bb: __m128i) {}
    fn mem_size() -> u32 { 0x20_0000 }
}

#[derive(Clone, Debug)]
pub struct Cnv2 {
    bb1: __m128i,
    div: u64,
    sqr: u64,
}

impl Default for Cnv2 {
    fn default() -> Self {
        Cnv2 {
            bb1: unsafe { _mm_set_epi64x(0, 0) },
            div: 0,
            sqr: 0,
        }
   }
}

unsafe fn int_sqrt_v2(input: u64) -> u64 {
    //let r = ((input as f64 + 18446744073709551616.0).sqrt() * 2.0 - 8589934592.0) as u64;

    let r = {
        let exp_double_bias = _mm_set_epi64x(0, (1023u64 << 52) as i64);
        let x = std::mem::transmute(_mm_add_epi64(_mm_cvtsi64_si128((input >> 12) as i64), exp_double_bias));
        let x = _mm_sqrt_sd(_mm_setzero_pd(), x);
        (_mm_cvtsi128_si64(_mm_sub_epi64(std::mem::transmute(x), exp_double_bias)) as u64) >> 19
    };

    let s = r >> 1;
    let b = r & 1;
    let r2 = s.wrapping_mul(s + b).wrapping_add(r << 32);
    r.wrapping_add((r2.wrapping_add(1 << 32) < input.wrapping_sub(s)) as u64).wrapping_sub((r2.wrapping_add(b) > input) as u64)
}
// XXX: seems sqr could be u32?

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
        let div = state[12];
        let sqr = state[13];
        Cnv2 { bb1, div, sqr }
    }
    fn shuffle_add(&mut self, mem: &mut [__m128i], j: u32, bb: __m128i, aa: __m128i) {
        let c1 = mem[(j ^ 1) as usize];
        let c2 = mem[(j ^ 2) as usize];
        let c3 = mem[(j ^ 3) as usize];
        unsafe {
            mem[(j ^ 1) as usize] = _mm_add_epi64(c3, self.bb1);
            mem[(j ^ 2) as usize] = _mm_add_epi64(c1, bb);
            mem[(j ^ 3) as usize] = _mm_add_epi64(c2, aa);
        }
    }
    fn pre_mul(&mut self, mut b0: u64, c0: u64, c1: u64) -> u64 {
        b0 ^= self.div ^ (self.sqr << 32);
        let dividend: u64 = c1;
        let divisor = ((c0 as u32).wrapping_add((self.sqr as u32) << 1)) | 0x8000_0001;
        self.div = u64::from((dividend / u64::from(divisor)) as u32) + ((dividend % u64::from(divisor)) << 32);
        self.sqr = unsafe { int_sqrt_v2(c0.wrapping_add(self.div)) };
        b0
    }
    unsafe fn post_mul(&mut self, mem: *mut u64, j: u32, mut lo: u64, mut hi: u64) -> (u64, u64) {
        let j = j as usize;
        *mem.add(j ^ 2) ^= hi;
        *mem.add(j ^ 2).add(1) ^= lo;
        hi ^= *mem.add(j ^ 4);
        lo ^= *mem.add(j ^ 4).add(1);
        (lo, hi)
    }
    fn end_iter(&mut self, bb: __m128i) {
        self.bb1 = bb;
    }
    fn mem_size() -> u32 { 0x20_0000 }
}

const DEBUG_ITERS: u32 = 3;

fn print_line(mem: &mut [__m128i], j: u32) {
    let j = j as usize;
    eprintln!("[j]={:x?}", mem[j]);
    eprintln!("[j ^ 1]={:x?}", mem[j ^ 1]);
    eprintln!("[j ^ 2]={:x?}", mem[j ^ 2]);
    eprintln!("[j ^ 3]={:x?}", mem[j ^ 3]);
}

#[target_feature(enable = "aes", enable = "sse4.1", enable = "sse4.2")]
unsafe fn mix_inner<V: Variant>(mem: &mut [__m128i], from: &[__m128i], mut var: V) {
    let mut aa = _mm_xor_si128(from[0], from[2]);
    let mut bb = _mm_xor_si128(from[1], from[3]);
    let mut a0 = _mm_extract_epi64(aa, 0) as u32;
    for i in 0..ITERS {
        let j = (a0 & (Cnv2::mem_size() - 0x10)) >> 4;
        if i < DEBUG_ITERS {
            eprintln!("{}: aes j: {:x}", i, j << 4);
        }
        let cc = mem[j as usize];
        let cc = _mm_aesenc_si128(cc, aa);
        var.shuffle_add(mem, j, bb, aa);
        if i < DEBUG_ITERS {
            eprintln!("{}: shuffleadd1: _b={:x?} _a={:x?}", i, bb, aa);
        }
        mem[j as usize] = _mm_xor_si128(bb, cc);
        if i < DEBUG_ITERS {
            eprintln!("{}: after aes:", i);
            print_line(mem, j);
        }
        let c0 = _mm_extract_epi64(cc, 0) as u64;
        let c1 = _mm_extract_epi64(cc, 1) as u64;
        let j = ((c0 as u32) & (Cnv2::mem_size() - 0x10)) >> 4;
        let b0 = *(&mem[j as usize] as *const _ as *const u64);
        let b1 = *(&mem[j as usize] as *const _ as *const u64).add(1);
        let b0 = var.pre_mul(b0, c0, c1);
        if i < DEBUG_ITERS {
            eprintln!("{}: mul j: {:x}", i, j << 4);
            eprintln!("{}: post-pre-mul var: {:x?}", i, var);
        }
        let (lo, hi) = mul64(c0, b0);
        let (lo, hi) = var.post_mul(mem.as_mut_ptr() as *mut _, j << 1, lo, hi);
        if i < DEBUG_ITERS {
            eprintln!("{}: ({:x}, {:x}) = tweaked_mul({:x}, {:x})", i, lo, hi, c0, b0);
        }
        var.shuffle_add(mem, j, bb, aa);
        a0 = a0.wrapping_add(hi as u32) ^ b0 as u32;
        aa = _mm_add_epi64(aa, _mm_set_epi64x(lo as i64, hi as i64));
        mem[j as usize] = aa;
        if i < DEBUG_ITERS {
            eprintln!("{}: after mul:", i);
            print_line(mem, j);
        }
        var.end_iter(bb);
        if i < DEBUG_ITERS {
            eprintln!("{}: _b1={:x?}", i, bb);
        }
        aa = _mm_xor_si128(aa, _mm_set_epi64x(b1 as i64, b0 as i64));
        bb = cc;
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
