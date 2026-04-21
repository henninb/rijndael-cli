use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::env;
use std::fs;
use std::process;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type HmacSha512   = Hmac<Sha512>;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: {} <ifname> <ofname> <keyfname> <ivfname>", args[0]);
        process::exit(1);
    }

    let ifname   = &args[1];
    let ofname   = &args[2];
    let keyfname = &args[3];
    let ivfname  = &args[4];

    println!("[ Rust | encrypt ] algorithm  : AES-256/CBC/PKCS7");

    let key_hex = fs::read_to_string(keyfname)
        .unwrap_or_else(|e| { eprintln!("ABORT: cannot read key file: {}", e); process::exit(1); });
    let key = hex::decode(key_hex.trim())
        .unwrap_or_else(|e| { eprintln!("ABORT: invalid key hex: {}", e); process::exit(1); });
    if key.len() != 32 {
        eprintln!("ABORT: key must be 32 bytes (64 hex chars), got {}", key.len());
        process::exit(1);
    }

    let iv_hex = fs::read_to_string(ivfname)
        .unwrap_or_else(|e| { eprintln!("ABORT: cannot read iv file: {}", e); process::exit(1); });
    let iv = hex::decode(iv_hex.trim())
        .unwrap_or_else(|e| { eprintln!("ABORT: invalid iv hex: {}", e); process::exit(1); });
    if iv.len() != 16 {
        eprintln!("ABORT: iv must be 16 bytes (32 hex chars), got {}", iv.len());
        process::exit(1);
    }

    let plaintext = fs::read(ifname)
        .unwrap_or_else(|e| { eprintln!("ABORT: cannot read input file: {}", e); process::exit(1); });

    let block_size = 16usize;
    let padded_len = plaintext.len() + (block_size - (plaintext.len() % block_size));
    println!("[ Rust | encrypt ] input      : {} bytes  ->  padded : {} bytes", plaintext.len(), padded_len);

    let key_arr: &[u8; 32] = key.as_slice().try_into().unwrap();
    let iv_arr:  &[u8; 16] = iv.as_slice().try_into().unwrap();

    let ciphertext = Aes256CbcEnc::new(key_arr.into(), iv_arr.into())
        .encrypt_padded_vec_mut::<Pkcs7>(&plaintext);

    fs::write(ofname, &ciphertext)
        .unwrap_or_else(|e| { eprintln!("ABORT: cannot write output file: {}", e); process::exit(1); });
    println!("[ Rust | encrypt ] output     : {}", ofname);

    let mut mac = HmacSha512::new_from_slice(&key)
        .unwrap_or_else(|e| { eprintln!("ABORT: HMAC init failed: {}", e); process::exit(1); });
    mac.update(&ciphertext);
    let sig = mac.finalize().into_bytes();
    fs::write(format!("{}.sig", ofname), &sig[..])
        .unwrap_or_else(|e| { eprintln!("ABORT: cannot write sig file: {}", e); process::exit(1); });
    println!("[ Rust | encrypt ] signature  : written");
}
