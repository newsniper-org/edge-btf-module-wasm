use wasm_bindgen::prelude::*;
use ckks_engine::*;

#[wasm_bindgen(getter_with_clone)]
pub struct CKKS {
    pub pk0: Vec<i64>,
    pub pk1: Vec<i64>,
    pub sk: Vec<i64>
}

impl Clone for CKKS {
    fn clone(&self) -> Self {
        Self {
            pk0: (*self).pk0.clone(),
            pk1: (*self).pk1.clone(),
            sk: (*self).sk.clone()
        }
    }
}

#[wasm_bindgen]
pub fn gen_ckks() -> CKKS {
    // Initialize key generator
    let keygen = KeyGenerator::new();
    let (public_key, secret_key) = keygen.generate_keys();

    CKKS {
        pk0: public_key.pk_0,
        pk1: public_key.pk_1,
        sk: secret_key.poly
    }
}

#[wasm_bindgen]
pub fn encrypt_ckks(pt: &[u8], pk0: &[i64], pk1: &[i64], degree: Option<usize>, modulus: Option<i64>) -> Vec<i64> {
    let encryptor = CKKSEncryptor::new(PublicKey { pk_0: pk0.to_vec(), pk_1: pk1.to_vec() }, CkksParameters {
        degree: if let Some(d) = degree {
            d
        } else {
            2048
        }, modulus: if let Some(m) = modulus {
            m
        } else {
            1000000000000007
        }
    });
    let ct = encryptor.encrypt_collection(pt);
    ct.coeffs
}

#[wasm_bindgen]
pub fn decrypt_ckks(ct: &[i64], sk: &[i64], degree: Option<usize>, modulus: Option<i64>) -> Vec<u8> {
    let decryptor = CKKSDecryptor::new(SecretKey { poly: sk.to_vec() }, CkksParameters {
        degree: if let Some(d) = degree {
            d
        } else {
            2048
        }, modulus: if let Some(m) = modulus {
            m
        } else {
            1000000000000007
        }
    });
    let ciphertext = Polynomial { coeffs: (*ct).to_vec() };
    let dt = decryptor.decrypt_as_int(&ciphertext);
    let pt = Vec::from_iter(dt.iter().map(|n: &i64| (*n) as u8));
    return pt;
}
