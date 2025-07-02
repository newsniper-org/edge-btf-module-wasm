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

// Kreyvium is a stream cipher based on Trivium but with enhanced security features.
// It was designed to be friendly for use in homomorphic encryption applications.

use std::{fmt};

/// The size of the Kreyvium state in bits
const STATE_SIZE: usize = 288;

/// The number of initialization rounds
const INIT_ROUNDS: usize = 4 * STATE_SIZE;

/// Kreyvium cipher implementation
#[wasm_bindgen(getter_with_clone)]
pub struct Kreyvium {
    /// Internal state of the cipher (288 bits)
    state: [bool; STATE_SIZE],
    /// Key (128 bits)
    key: [bool; 128],
    /// IV (128 bits)
    iv: [bool; 128],
}

impl Kreyvium {
    /// Create a new Kreyvium cipher instance with the given key and IV
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let mut k_bits = [false; 128];
        let mut iv_bits = [false; 128];
        
        // Convert key and IV to bit arrays
        for i in 0..16 {
            for j in 0..8 {
                k_bits[i * 8 + j] = (key[i] >> j) & 1 == 1;
                iv_bits[i * 8 + j] = (iv[i] >> j) & 1 == 1;
            }
        }
        
        // Initialize state
        let mut state = [false; STATE_SIZE];
        
        // Initialize first register (s1 to s93)
        for i in 0..93 {
            state[i] = false;
        }
        
        // Initialize second register (s94 to s177)
        for i in 0..84 {
            state[93 + i] = iv_bits[i];
        }
        
        // Set all bits of the third register to 1 (s178 to s288)
        for i in 177..STATE_SIZE {
            state[i] = true;
        }
        
        let mut kreyvium = Kreyvium { state, key: k_bits, iv: iv_bits };
        
        // Run initialization phase
        kreyvium.initialize();
        
        kreyvium
    }
    
    /// Initialize the cipher by running INIT_ROUNDS update steps
    fn initialize(&mut self) {
        for _ in 0..INIT_ROUNDS {
            // Calculate t1, t2, t3 similar to the update function but with key and IV feedback
            let t1 = self.state[65] ^ self.state[92];
            let t2 = self.state[161] ^ self.state[176];
            let t3 = self.state[242] ^ self.state[287];
            
            // Additional terms for initialization
            let t4 = t1 ^ self.state[90] & self.state[91] ^ self.state[170] ^ self.key[0];
            let t5 = t2 ^ self.state[174] & self.state[175] ^ self.state[263] ^ self.iv[0];
            let t6 = t3 ^ self.state[285] & self.state[286] ^ self.state[68] ^ true; // Constant 1
            
            // Shift the state
            for i in (1..93).rev() {
                self.state[i] = self.state[i-1];
            }
            for i in (94..177).rev() {
                self.state[i] = self.state[i-1];
            }
            for i in (178..STATE_SIZE).rev() {
                self.state[i] = self.state[i-1];
            }
            
            // Update the first bits of each register
            self.state[0] = t6;
            self.state[93] = t4;
            self.state[177] = t5;
            
            // Rotate key and IV for the next round
            self.rotate_key_iv();
        }
    }
    
    /// Rotate the key and IV arrays (shift right)
    fn rotate_key_iv(&mut self) {
        let k_last = self.key[127];
        let iv_last = self.iv[127];
        
        for i in (1..128).rev() {
            self.key[i] = self.key[i-1];
            self.iv[i] = self.iv[i-1];
        }
        
        self.key[0] = k_last;
        self.iv[0] = iv_last;
    }
    
    /// Generate the next keystream bit
    pub fn next_bit(&mut self) -> bool {
        // Calculate output bit
        let output = self.state[65] ^ self.state[92] ^ self.state[161] ^ 
                    self.state[176] ^ self.state[242] ^ self.state[287];
        
        // Calculate t1, t2, t3
        let t1 = self.state[65] ^ self.state[92];
        let t2 = self.state[161] ^ self.state[176];
        let t3 = self.state[242] ^ self.state[287];
        
        let t4 = t1 ^ self.state[90] & self.state[91] ^ self.state[170];
        let t5 = t2 ^ self.state[174] & self.state[175] ^ self.state[263];
        let t6 = t3 ^ self.state[285] & self.state[286] ^ self.state[68];
        
        // Shift the state
        for i in (1..93).rev() {
            self.state[i] = self.state[i-1];
        }
        for i in (94..177).rev() {
            self.state[i] = self.state[i-1];
        }
        for i in (178..STATE_SIZE).rev() {
            self.state[i] = self.state[i-1];
        }
        
        // Update the first bits of each register
        self.state[0] = t6;
        self.state[93] = t4;
        self.state[177] = t5;
        
        output
    }
    
    /// Generate keystream bytes
    pub fn keystream(&mut self, length: usize) -> Vec<u8> {
        let mut result = vec![0u8; length];
        
        for byte_idx in 0..length {
            let mut byte = 0u8;
            for bit_idx in 0..8 {
                if self.next_bit() {
                    byte |= 1 << bit_idx;
                }
            }
            result[byte_idx] = byte;
        }
        
        result
    }
    
    /// Encrypt or decrypt data (XOR with keystream)
    pub fn process(&mut self, data: &[u8]) -> Vec<u8> {
        let keystream = self.keystream(data.len());
        data.iter()
            .zip(keystream.iter())
            .map(|(&d, &k)| d ^ k)
            .collect()
    }
}

impl fmt::Debug for Kreyvium {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Kreyvium {{ state: [..], key: [..], iv: [..] }}")
    }
}

/// Utility function to convert a hex string to bytes
#[wasm_bindgen]
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>,String> {
    let result = match hex::decode(hex) {
        Ok(ok) => Ok(ok),
        Err(hex::FromHexError::InvalidHexCharacter { c, index }) => Err(format!("InvalidHexCharacter: '{c}' {index}")),
        Err(hex::FromHexError::OddLength) => Err(format!("OddLength")),
        Err(hex::FromHexError::InvalidStringLength) => Err(format!("InvalidStringLength"))
    };
    result
}

/// Utility function to convert bytes to a hex string
#[wasm_bindgen]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}


