// copyright 2017 Kaz Wesley

use std::arch::x86_64::*;

fn update_key(xmm0: __m128i, xmm2: __m128i) -> __m128i {
    unsafe {
        let xmm3 = _mm_slli_si128(xmm0, 0x4);
        let xmm0 = _mm_xor_si128(xmm0, xmm3);
        let xmm3 = _mm_slli_si128(xmm3, 0x4);
        let xmm0 = _mm_xor_si128(xmm0, xmm3);
        let xmm3 = _mm_slli_si128(xmm3, 0x4);
        let xmm0 = _mm_xor_si128(xmm0, xmm3);
        _mm_xor_si128(xmm0, xmm2)
    }
}

macro_rules! round_term {
    ($round:expr, $mask:expr, $in:ident) => {{
        _mm_shuffle_epi32(_mm_aeskeygenassist_si128($in, $round), $mask)
    }};
}

pub fn genkey(k0: __m128i, k1: __m128i) -> [__m128i; 10] {
    unsafe {
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
}
