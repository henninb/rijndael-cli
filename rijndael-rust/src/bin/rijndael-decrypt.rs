use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::env;
use std::fs;
use std::path::Path;
use std::process;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
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

    println!("[ Rust | decrypt ] algorithm  : AES-256/CBC/PKCS7");

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

    let ciphertext = fs::read(ifname)
        .unwrap_or_else(|e| { eprintln!("ABORT: cannot read input file: {}", e); process::exit(1); });

    println!("[ Rust | decrypt ] input      : {} bytes", ciphertext.len());

    let sig_path = format!("{}.sig", ifname);
    if Path::new(&sig_path).exists() {
        let stored_sig = fs::read(&sig_path)
            .unwrap_or_else(|e| { eprintln!("ABORT: cannot read sig file: {}", e); process::exit(1); });
        let mut mac = HmacSha512::new_from_slice(&key)
            .unwrap_or_else(|e| { eprintln!("ABORT: HMAC init failed: {}", e); process::exit(1); });
        mac.update(&ciphertext);
        mac.verify_slice(&stored_sig)
            .unwrap_or_else(|_| { eprintln!("ABORT: MAC verification failed"); process::exit(1); });
        println!("[ Rust | decrypt ] MAC        : verified OK");
    } else {
        println!("[ Rust | decrypt ] WARNING    : no .sig file — skipping MAC verification");
    }

    let key_arr: &[u8; 32] = key.as_slice().try_into().unwrap();
    let iv_arr:  &[u8; 16] = iv.as_slice().try_into().unwrap();

    let plaintext = Aes256CbcDec::new(key_arr.into(), iv_arr.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
        .unwrap_or_else(|e| { eprintln!("ABORT: decryption/unpad failed: {:?}", e); process::exit(1); });

    fs::write(ofname, &plaintext)
        .unwrap_or_else(|e| { eprintln!("ABORT: cannot write output file: {}", e); process::exit(1); });
    println!("[ Rust | decrypt ] output     : {}", ofname);
}
