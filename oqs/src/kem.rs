use crate::*;
use std::ptr::NonNull;
use crate::ffi::kem as ffi;

use std::os::raw;


macro_rules! newtype_buffer {
    ($name: ident) => {
        #[derive(Debug, Clone, PartialEq)]
        pub struct $name {
            bytes: Vec<u8>,
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.bytes.as_ref()
            }
        }

        impl $name {
            pub fn len(&self) -> usize {
                self.bytes.len()
            }
        }
   }
}

newtype_buffer!(PublicKey);
newtype_buffer!(SecretKey);
newtype_buffer!(Ciphertext);
newtype_buffer!(SharedSecret);


macro_rules! implement_kems {
    { $( $kem: ident: $oqs_id: ident),* $(,)? } => (
        #[derive(Clone, Copy, Debug)]
        pub enum Algorithm {
            $(
                $kem,
            )*
        }

        fn algorithm_to_id(algorithm: Algorithm) -> *const raw::c_char {
            let id: &[u8] = match algorithm {
                $(
                    Algorithm::$kem => &ffi::$oqs_id[..],
                )*
            };
            id as *const _ as *const i8
        }

        $(
            #[cfg(test)]
            #[allow(non_snake_case)]
            mod $kem {
                use super::*;
                #[test]
                fn test_encaps_decaps() -> Result<()> {
                    let alg = Algorithm::$kem;
                    let kem = Kem::new(alg)?;
                    let (pk, sk) = kem.keypair()?;
                    let (ct, ss1) = kem.encapsulate(&pk)?;
                    let ss2 = kem.decapsulate(&sk, &ct)?;
                    assert_eq!(ss1, ss2, "shared secret not equal!");
                    Ok(())
                }
            }
        )*
    )
}

implement_kems! {
    Default: OQS_KEM_alg_default,
    BikeL1Cpa: OQS_KEM_alg_bike1_l1_cpa,
    BikeL3Cpa: OQS_KEM_alg_bike1_l3_cpa,
    BikeL1Fo: OQS_KEM_alg_bike1_l1_fo,
    BikeL3Fo: OQS_KEM_alg_bike1_l3_fo,
    ClassicMcEliece348864: OQS_KEM_alg_classic_mceliece_348864,
    ClassicMcEliece348864f: OQS_KEM_alg_classic_mceliece_348864f,
    ClassicMcEliece460896: OQS_KEM_alg_classic_mceliece_460896,
    ClassicMcEliece460896f: OQS_KEM_alg_classic_mceliece_460896f,
    ClassicMcEliece6688128: OQS_KEM_alg_classic_mceliece_6688128,
    ClassicMcEliece6688128f: OQS_KEM_alg_classic_mceliece_6688128f,
    ClassicMcEliece6960119: OQS_KEM_alg_classic_mceliece_6960119,
    ClassicMcEliece6960119f: OQS_KEM_alg_classic_mceliece_6960119f,
    ClassicMcEliece8192128: OQS_KEM_alg_classic_mceliece_8192128,
    ClassicMcEliece8192128f: OQS_KEM_alg_classic_mceliece_8192128f,
    Kyber512: OQS_KEM_alg_kyber_512,
    Kyber768: OQS_KEM_alg_kyber_768,
    Kyber1024: OQS_KEM_alg_kyber_1024,
    Kyber512_90s: OQS_KEM_alg_kyber_512_90s,
    Kyber768_90s: OQS_KEM_alg_kyber_768_90s,
    Kyber1024_90s: OQS_KEM_alg_kyber_1024_90s,
    LedaKemLt12: OQS_KEM_alg_ledacrypt_ledakemlt12,
    LedaKemLt32: OQS_KEM_alg_ledacrypt_ledakemlt32,
    LedaKemLt52: OQS_KEM_alg_ledacrypt_ledakemlt52,
    NewHope512cca: OQS_KEM_alg_newhope_512cca,
    NewHope1024cca: OQS_KEM_alg_newhope_1024cca,
    NTRUHPS2048509: OQS_KEM_alg_ntru_hps2048509,
    NTRUHPS2048677: OQS_KEM_alg_ntru_hps2048677,
    NTRUHPS4096812: OQS_KEM_alg_ntru_hps4096821,
    NTRUHRSS701: OQS_KEM_alg_ntru_hrss701,
    Lightsaber: OQS_KEM_alg_saber_lightsaber,
    Saber: OQS_KEM_alg_saber_saber,
    Firesaber: OQS_KEM_alg_saber_firesaber,
    Babybear: OQS_KEM_alg_threebears_babybear,
    BabybearEphem: OQS_KEM_alg_threebears_babybear_ephem,
    Mamabear: OQS_KEM_alg_threebears_mamabear,
    MamabearEphem: OQS_KEM_alg_threebears_mamabear_ephem,
    Papabear: OQS_KEM_alg_threebears_papabear,
    PapabearEphem: OQS_KEM_alg_threebears_papabear_ephem,
    FrodoKem640Aes: OQS_KEM_alg_frodokem_640_aes,
    FrodoKem640Shake: OQS_KEM_alg_frodokem_640_shake,
    FrodoKem976Aes: OQS_KEM_alg_frodokem_976_aes,
    FrodoKem967Shake: OQS_KEM_alg_frodokem_976_shake,
    FrodoKem1344Aes: OQS_KEM_alg_frodokem_1344_aes,
    FrodoKem1344Shake: OQS_KEM_alg_frodokem_1344_shake,
    SidhP434: OQS_KEM_alg_sidh_p434,
    SidhP503: OQS_KEM_alg_sidh_p503,
    SidhP610: OQS_KEM_alg_sidh_p610,
    SidhP751: OQS_KEM_alg_sidh_p751,
    SidhP434Compressed: OQS_KEM_alg_sidh_p434_compressed,
    SidhP503Compressed: OQS_KEM_alg_sidh_p503_compressed,
    SidhP610Compressed: OQS_KEM_alg_sidh_p610_compressed,
    SidhP751Compressed: OQS_KEM_alg_sidh_p751_compressed,
    SikeP434: OQS_KEM_alg_sike_p434,
    SikeP503: OQS_KEM_alg_sike_p503,
    SikeP610: OQS_KEM_alg_sike_p610,
    SikeP751: OQS_KEM_alg_sike_p751,
    SikeP434Compressed: OQS_KEM_alg_sike_p434_compressed,
    SikeP503Compressed: OQS_KEM_alg_sike_p503_compressed,
    SikeP610Compressed: OQS_KEM_alg_sike_p610_compressed,
    SikeP751Compressed: OQS_KEM_alg_sike_p751_compressed,
}



pub struct Kem {
    kem: NonNull<ffi::OQS_KEM>,
}

impl Drop for Kem {
    fn drop(&mut self) {
        unsafe { ffi::OQS_KEM_free(self.kem.as_ptr()) };
    }
}

impl Kem {
    pub fn new(algorithm: Algorithm) -> Result<Self> {
        let kem = unsafe { ffi::OQS_KEM_new(algorithm_to_id(algorithm)) };
        NonNull::new(kem).map_or_else(|| Err(Error::AlgorithmDisabled), |kem| Ok(Self{ kem }))
    }

    pub fn keypair(&self) -> Result<(PublicKey, SecretKey)> {
        let kem = unsafe { self.kem.as_ref() };
        let func = kem.keypair.unwrap();
        let mut pk = PublicKey { bytes: Vec::with_capacity(kem.length_public_key) };
        let mut sk = SecretKey { bytes: Vec::with_capacity(kem.length_secret_key) };
        let status = unsafe { func(pk.bytes.as_mut_ptr(), sk.bytes.as_mut_ptr())};
        // update the lengths of the vecs
        unsafe {
            pk.bytes.set_len(kem.length_public_key);
            sk.bytes.set_len(kem.length_secret_key);
        }
        status_to_result(status)?;
        Ok((pk, sk))
    }

    pub fn encapsulate(&self, pk: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
        let kem = unsafe { self.kem.as_ref() };
        assert_eq!(pk.len(), kem.length_public_key);
        let func = kem.encaps.unwrap();
        let mut ct = Ciphertext { bytes: Vec::with_capacity(kem.length_ciphertext) };
        let mut ss = SharedSecret { bytes: Vec::with_capacity(kem.length_shared_secret) };
        let status = unsafe { func(ct.bytes.as_mut_ptr(), ss.bytes.as_mut_ptr(), pk.bytes.as_ptr()) };
        status_to_result(status)?;
        unsafe {
            ct.bytes.set_len(kem.length_ciphertext);
            ss.bytes.set_len(kem.length_shared_secret);
        }
        Ok((ct, ss))
    }

    pub fn decapsulate(&self, sk: &SecretKey, ct: &Ciphertext) -> Result<SharedSecret> {
        let kem = unsafe { self.kem.as_ref() };
        assert_eq!(sk.len(), kem.length_secret_key);
        assert_eq!(ct.len(), kem.length_ciphertext);
        let mut ss = SharedSecret { bytes: Vec::with_capacity(kem.length_shared_secret) };
        let func = kem.decaps.unwrap();
        let status = unsafe { func(ss.bytes.as_mut_ptr(), ct.bytes.as_ptr(), sk.bytes.as_ptr()) };
        status_to_result(status)?;
        unsafe { ss.bytes.set_len(kem.length_shared_secret) };
        Ok(ss)
    }
}
