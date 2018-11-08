// copyright 2017 Kaz Wesley

#![feature(asm)]
#![feature(stdsimd)]

mod cn_aesni;
mod mmap;
mod state;

use blake_hash::digest::Digest;
use skein_hash::digest::generic_array::typenum::U32;
use skein_hash::digest::generic_array::GenericArray;
use std::arch::x86_64::__m128i as i64x2;
use std::str::FromStr;
use byteorder::{ByteOrder, LE};

use self::mmap::Mmap;
use self::state::State;

fn finalize(mut data: State) -> GenericArray<u8, U32> {
    keccak::f1600((&mut data).into());
    let bytes: &[u8; 200] = (&data).into();
    match bytes[0] & 3 {
        0 => blake_hash::Blake256::digest(bytes),
        1 => groestl_aesni::Groestl256::digest(bytes),
        2 => jh_x86_64::Jh256::digest(bytes),
        3 => skein_hash::Skein512::<U32>::digest(bytes),
        _ => unreachable!(),
    }
}

fn set_nonce(blob: &mut [u8], nonce: u32) {
    LE::write_u32(&mut blob[39..43], nonce);
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

pub use crate::mmap::Policy as AllocPolicy;

pub struct Hasher(Hasher_);
enum Hasher_ {
    CryptoNight0{ memory: Mmap<[i64x2; 1 << 17]> },
    //CryptoNight1{ memory: Mmap<[i64x2; 1 << 17]> },
    CryptoNight2{ memory: Mmap<[i64x2; 1 << 17]> },
}
impl Hasher {
    pub fn new(algo: Algo, alloc: AllocPolicy) -> Self {
        Hasher(match algo {
            Algo::Cn0 => Hasher_::CryptoNight0 { memory: Mmap::new(alloc) },
            //Algo::Cn1 => Hasher_::CryptoNight1 { memory: Mmap::default() },
            Algo::Cn2 => Hasher_::CryptoNight2 { memory: Mmap::new(alloc) },
        })
    }
    pub fn hashes<'a, Noncer: Iterator<Item = u32> + 'static>(&'a mut self, mut blob: Box<[u8]>, noncer: Noncer) -> Hashes<'a> {
        match &mut self.0 {
            Hasher_::CryptoNight0 { memory } => {
                let algo = CryptoNight::<_, cn_aesni::Cnv0>::new(noncer, &mut memory[..], &mut blob[..]);
                Hashes::new(&mut memory[..], blob, Box::new(algo))
            }
            /*
            Hasher_::CryptoNight1 { memory } => {
                let algo = CryptoNight1::new(&mut memory[..], noncer, &mut blob);
                Hashes::new(&mut memory[..], blob, Box::new(algo))
            }*/
            Hasher_::CryptoNight2 { memory } => {
                let algo = CryptoNight::<_, cn_aesni::Cnv2>::new(noncer, &mut memory[..], &mut blob[..]);
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
struct CryptoNight<Noncer, Variant> {
    state: State,
    variant: Variant,
    n: Noncer,
}
impl<Noncer: Iterator<Item = u32>, Variant: cn_aesni::Variant> CryptoNight<Noncer, Variant> {
    fn new(mut n: Noncer, mem: &mut [i64x2], blob: &mut [u8]) -> Self {
        set_nonce(blob, n.next().unwrap());
        let state = State::from(sha3_plus::Keccak256Full::digest(blob));
        let variant = Variant::new(blob, (&state).into());
        cn_aesni::explode(mem, (&state).into());
        CryptoNight { state, variant, n }
    }
}
impl<Noncer: Iterator<Item = u32>, Variant: cn_aesni::Variant> Impl for CryptoNight<Noncer, Variant> {
    fn next_hash(&mut self, mem: &mut [i64x2], blob: &mut [u8]) -> GenericArray<u8, U32> {
        set_nonce(blob, self.n.next().unwrap());
        let mut prev_state = std::mem::replace(&mut self.state, State::from(sha3_plus::Keccak256Full::digest(blob)));
        let prev_var = std::mem::replace(&mut self.variant, Variant::new(blob, (&self.state).into()));
        cn_aesni::mix(mem, (&prev_state).into(), prev_var);
        cn_aesni::transplode((&mut prev_state).into(), mem, (&self.state).into());
        finalize(prev_state)
    }
}

pub fn hash<V: cn_aesni::Variant>(blob: &[u8]) -> GenericArray<u8, U32> {
    hash_after_keccak::<V>(blob, sha3_plus::Keccak256Full::digest(blob))
}

pub fn hash_after_keccak<V: cn_aesni::Variant>(blob: &[u8], after_keccak: GenericArray<u8, blake_hash::digest::generic_array::typenum::U200>) -> GenericArray<u8, U32> {
    let mut mem = Mmap::<[i64x2; 1 << 17]>::default();
    let mut state = State::from(after_keccak);
    let variant = V::new(blob, (&state).into());
    cn_aesni::explode(&mut mem[..], (&state).into());
    cn_aesni::mix(&mut mem[..], (&state).into(), variant);
    cn_aesni::implode((&mut state).into(), &mem[..]);
    finalize(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::{hex, hex_impl};

    fn test_independent_cases<V: cn_aesni::Variant>(input: &[&[u8]], keccak: &[[u8; 200]], output: &[[u8; 32]]) {
        assert_eq!(input.len(), output.len());
        for ((&blob, &expected), &expected_keccak) in input.iter().zip(output).zip(keccak) {
            let keccak = sha3_plus::Keccak256Full::digest(blob);
            assert_eq!(&keccak[..], &expected_keccak[..]);
            assert_eq!(&hash_after_keccak::<V>(blob, keccak)[..], expected);
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
        const KECCAK_V0: &[[u8; 200]] = &[
            hex!("628EC2906870EA008E81AD1901BA731E06D4A94D5EACFEF0276DBC9D91CD28602FEDFB134E5A4C956BC7782B36CB71F46624DDAD5B1AB6EAE1E129A07BB4BDF901DBD2D1C2A23F9BFD40265DF32464142EDA9689364A943779B57B6B20017B14895643218B52A2ED4E18F80E0E6415900C91246951ECA6049504BF275E5CE0D23DEA3749BA397F6E394B7E0475C701D184B1339E7E14A5E923053CEA50C49981EDE41EA861BF53FB4FBD72A922CE8B57BECAD7CC8DC1D17F8C4555B275E27E50B840E6B8A7B4E74F"),
            hex!("94780A76D7F903A2DE81AACE1A84EA28F74177BDEC99ECCC4317C7B9D9CFFF0E44FB80F8DF551D5845239D814C620C9E0436378AC1FB83C3F8BA9ADD9A484655F02C3C0215494537F6D078AB11CE6BADA86AAF50DC7C58C4076A7A27D835090581248808B0A71906D2497A9C8DB815B8C22E3BDA1D8D49BCC1E8E68F3E2119B8C9915F24A226201BADF239F38D5F43A337842DAB3B45B0BB2D00CD7202CE2BF6BC1DE4B4AD24ABE24D073C8057B97E97E856DCE8BB0F3A1E0CE2135BFEF64D32E0950B6D8BB30514"),
            hex!("21BC6CEE441F1E124E25A486597006AC58713A4CEBAB192FD387CE607129BD290A7A89D3007C3ECC1116845DCF72A7E3A093C6E973562E464F9524970C1349E9DFF4888EFF9F33633A4620208C682CC372990E6CF5DF14795B2DD23986F773C2F3DB24BC7E2991EEE8C6DBCA7016D2A874D6AC50E7DFCEA7CAA761BB0913FA274F22C5D16EB02394598D295B946AEF0DF1FCCE3F1AA10582BF1397592D353D260EDD0610B3F80C29F1A1B23B6ED86D63BE68E3FB05BF38FE20FB1D895458C5C2E7E7AEA5DA026631"),
            hex!("9D97CD4C447D6EF44565CE2C2C03D4C36206614A11CD12699066F710C6BE6E36F93B4F12C391076963CEBDE53594BA37C4530A910BAA00E16BEF75F0310099188CC1446A057156FFC4CE594B4D9AE8F6F775D15ED1B58D82292AB72533528B9A846949543A430B7F70B49D1AE1A1DF65A90C067CB222985E955BBC3185A4184470D2CFA97B3BF1BC8F8EB9D15582AF640D0A9FB938EE9E0F79819EACAD4583705A560EF408C7581709CCA951FE0AD3EFA809D6C783F2C0462B50A7705BFADBD685118DCD956E43AB"),
        ];
        const OUT_V0: &[[u8; 32]] = &[
            hex!("2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5"),
            hex!("722fa8ccd594d40e4a41f3822734304c8d5eff7e1b528408e2229da38ba553c4"),
            hex!("bbec2cacf69866a8e740380fe7b818fc78f8571221742d729d9d02d7f8989b87"),
            hex!("b1257de4efc5ce28c6b40ceb1c6c8f812a64634eb3e81c5220bee9b2b76a6f05"),
        ];
        test_independent_cases::<cn_aesni::Cnv0>(IN_V0, KECCAK_V0, OUT_V0);
    }

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
        const KECCAK_V2: &[[u8; 200]] = &[
            hex!("AF6FE96F8CB409BDD2A61FB837E346F1A28007B0F078A8D68BC1224B6FCFCC3C39F1244DB8C0AF06E94173DB4A54038A2F7A6A9C729928B5EC79668A30CBF5F266110665E23E891EA4EE2337FB304B35BF8D9C2E4C3524E52E62DB67B0B170487A68A34F8026A81B35DC835C60B356D2C411AD227B6C67E30E9B57BA34B3CF27FCCECAE972850CF3889BB3FF8347B55A5710D58086973D12D75A3340A39430B65EE2F4BE27C21E7B39F47341DD036FE13BF43BB2C55BCE498A3ADCBF07397EA66062B66D56CD8136"),
            hex!("9D435346D0FE1107CE94DF91D7E66F03450C4A2851BCD1557EB3B5C394B77DE94E1E1550D8D12ED0054E9B4413CF43FEB1B91D6FF03E0895E1E55E563E6CE778968AA9535E57BB2EAE559B6915A6C2E2EE2CA72B248D3A34DA62B23C6A7A4A531E064C2ED1D10C3EB7C1A60D032B5B93B8F3717F9BBEF51C88E9C047A5AA33D4F63C50512C2CFCC760D060A8454ED9245C5BD2561AF2D26430289E506C73618896433D752FB0D54003B006435466BBB4763FA236DEB1B48B93F89D621161249C29CE189382A93829"),
            hex!("EDC9E0794192D5EED5BFB913D995E999E27118268520CC6D40E19F79A0A737C656290B9387E041893761A1F17313F15F83ECBDC682AE4A7C062D1D948A0935F7D32256171FC1B6BDD8BDA6B1A7B1109C3EF0EB7320701EB3D09D77D5773E00D8B6AF22A59AAF3C6DB2B0CBCB012AC904817BA550003FEAF69F2EE04A92F38959C5E74D2B3EA020F49D5818EF0796A0B46A34DDFA895AF8E6E05CA7D814F0F369F1B4120F8CC7B9B9C78EF83EDDAB61097FE7C578E2DE587E409CD07B749DB92AD98A4FE5E41D08F0"),
            hex!("2D317EABB6E8040D5A9D0C95B6E1F6EF94F259BE20E46F641BE32F2A30446F66E85440B1A344B0BF80AC51A841829629DF4DC6740F4715D543A6761427BCFFADCE5F754215D27D3AA124588FDBE0D4AD20DA7EDCC57C59D929A64BFAE00E5DE8958AB92AA463B0A7464D76A349CEC23DEDF734DB3B5BDEB66C1F041096ADA36882E5F73283A8C80D71AD9620F9A83AD0D87FA28D744AAA2D6CA55D4BE0218A33A2C1E5D10D79A4F61B462E14A4B66E544D18524CAC72748E0D4F108AAA66D17D083C559F69366DE0"),
            hex!("DA29CE0E001BF2541D94E2D882E842B86E7B6ECDA114BAA53B8C9E35CCF921ACEB2A7D063C2A554E33BEE0B09BA2605780062EA3E9DB78014385DA024B24A49161973174EC08ECAE4BF473579C6439C46F3F3850E39EA4131F264AF0BB2CC6416229DB86C15F1B3D7E723FD53528A456D049786E7A9928B9E75B2FBD5282312A8E5C492CA674B2D99CF4AC3FEF133A14C52D6B5436582722585D64F579A713E51F5FA8CF8C49811F01BA15A0A264D579E18722573D0D20CC524B12566988BDC9F14A810BA07FD919"),
            hex!("EC9E49DF136517FDC5050B608716EA0DC48D00A17FCB988547F9C7FAD22B21AEE739D5270682D105D4A940944B5A58AFFBBCFEA19584B001E5EBE77191812D756B8C583F64D061D6FA1DA2AE74B4AB3B878D35A90A7BF1A1C3D007734DEC63E9F75DE8C0B8766A096288027A1877A81F32D45163608579CC9D86292366B0E4108A88AC86E5D070963D05C3B9FDE03FDD3C6013397F2012235AC80E83242DF7958B2DBA798A680E6A0CAC1F440A7EB8241B815202FFCE2DD730C9781C641FA1242A685A1E1447F1FA"),
            hex!("A747012E31A22161C9EAB2B6C5DA72F462E6AE52A68BA1E4EBD12BA55D7D738B5B8DEBAD66565496506BC35223AE04093D14976CED6EBC23B977F6BD6B1BF074387CE3F3D182E17A8372E390D6AE6D4090BEEB0B014A88CFEF6BC5AA3BF5DE89B5E728DC43F81896A469887DED3146B73AE93C6919899BE5442424A4B6B75744B6CB928A36949A16DFEB6853E8F048AB3B1F94BBB7C8FE9B991B2C5EABF4C5802234AE29BA31564642CDE26E2CD7ADF8F6092474E5427D7399407E999C230D83FE4D8AAF949FCEB9"),
            hex!("2896B97426233AFB921A6FCEC1E4228CA52553556F52C2AF818D97188531B2FC0D1DF9F06C1E7BB2191A6FF11F1ADA4EBDB825E4589BAB1D82DDD222DE1898E4C3E99CB76D1ED38554DA533401F43BF5077137B490A82D3EE00E7CEEE57DE7819584545D5FEE77FC0FED7AC7C6F146856F514F9B049A32006F284976CFDDFC458F385B2877E0CECF7523D8BF5E84CC6DF590763AFDB0ACF88BD08D4793ECFBF938B16126505B68F9C8E0958CF2C3E3F6FBAF0643339213CD7D41108BF6237CC1789CC06A3655E045"),
            hex!("67852C5BF657E1369A09DBCE2F6358526653DC9C973C1751B95BFE3AD0DE310009F9D6CE44509A70794EE079C692D97020D5F2C1E6625D9DBC17B2294EA8C0306BAB83B4C646D2A66F9510454541E5222869AC0D5385A37315E410AE35F479A56632A0A968E4908340B619235C58D72C02198A46FF7CD3F81E390B3F010BE4F4AF19FFF21B8B5C10244C5254A7081789060117DFD866B1950B370840AF1C7D207C64AD088EDE25C82810E35A38F637312B1AE8BA142E2C24364F2744C3B0D41D80EDD5E14A63D207"),
            hex!("3F31110D8695A7E96B3712587DEAD79F380BCC80F0BF8774B7CC705DF3C6DBBA14E56DA0025D031090014B690ACBF3ACE301589BC3AFD2F1BF86ACE62224E235E11DCC44273305548C1E3FC4CE763E7D35204D5F30DCBC63419E17012FD92F58A040D3324E247BC92301C595A2CAAEF91C470347F96369AAE20941B3ABAE9172D6618EB13A8143C96362F69329C84EDE127A1FFDF10B9DF63E889E351DF881F136FC857AF38C47C75E9250822F0CA1D3134FFD1779E5B2CC7B8FB3B8A6DBC22A2C158326F4A29966"),
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
        test_independent_cases::<cn_aesni::Cnv2>(IN_V2, KECCAK_V2, OUT_V2);
    }

    #[test]
    fn test_pipeline() {
        let blob0 = [0u8; 64];
        let pip_blob: Vec<_> = blob0.iter().cloned().collect();
        let pip_blob = pip_blob.into_boxed_slice();
        let mut hasher = Hasher::new(Algo::Cn2, AllocPolicy::AllowSlow);
        let mut pipeline = hasher.hashes(pip_blob, 0..);
        let mut blob1 = blob0;
        set_nonce(&mut blob1, 1);
        assert_eq!(&hash::<cn_aesni::Cnv2>(&blob0[..])[..], &pipeline.next().unwrap()[..]);
        assert_eq!(&hash::<cn_aesni::Cnv2>(&blob1[..])[..], &pipeline.next().unwrap()[..]);
    }
}
