/// Integration tests for the Rust Rijndael encrypt/decrypt binaries.
///
/// Tests are subprocess-based: they build the binaries (if needed) and invoke
/// them with temporary files, checking exit codes, file contents, and HMAC
/// correctness.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const KEY_HEX: &str = "594193e330c8e8312f244c9cff045b73e66c301c30eb3bf0ec943a25e7a45650";
const IV_HEX: &str = "2cef85f5259ae311034de17fda3b8369";
const WRONG_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const WRONG_IV_HEX: &str = "ffffffffffffffffffffffffffffffff";
const PLAINTEXT: &[u8] = b"my message to you, let's win"; // 28 bytes

static BUILD_DONE: OnceLock<bool> = OnceLock::new();

fn ensure_built() {
    BUILD_DONE.get_or_init(|| {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let status = Command::new("cargo")
            .args(["build", "--release"])
            .current_dir(manifest_dir)
            .status()
            .expect("cargo build failed to launch");
        assert!(status.success(), "cargo build --release failed");
        true
    });
}

fn bin(name: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("target")
        .join("release")
        .join(name)
}

struct Workspace {
    dir: tempfile::TempDir,
}

impl Workspace {
    fn new() -> Self {
        Workspace {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write(&self, name: &str, data: &[u8]) -> PathBuf {
        let p = self.path(name);
        fs::write(&p, data).expect("write");
        p
    }

    fn write_str(&self, name: &str, data: &str) -> PathBuf {
        self.write(name, data.as_bytes())
    }

    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.path(name)).expect("read")
    }

    fn setup_keys(&self) {
        self.write_str("input.key", KEY_HEX);
        self.write_str("input.iv", IV_HEX);
    }

    fn encrypt(&self, plaintext: &[u8]) -> std::process::Output {
        self.write("input.txt", plaintext);
        Command::new(bin("rijndael-encrypt"))
            .args([
                self.path("input.txt"),
                self.path("output.rij"),
                self.path("input.key"),
                self.path("input.iv"),
            ])
            .output()
            .expect("encrypt exec")
    }

    fn decrypt_with(
        &self,
        ct_file: PathBuf,
        key_hex: &str,
        iv_hex: &str,
    ) -> std::process::Output {
        self.write_str("dec.key", key_hex);
        self.write_str("dec.iv", iv_hex);
        Command::new(bin("rijndael-decrypt"))
            .args([ct_file, self.path("decrypted.txt"), self.path("dec.key"), self.path("dec.iv")])
            .output()
            .expect("decrypt exec")
    }

    fn decrypt(&self) -> std::process::Output {
        self.decrypt_with(self.path("output.rij"), KEY_HEX, IV_HEX)
    }
}

// ---------------------------------------------------------------------------
// Encrypt – output structure
// ---------------------------------------------------------------------------

#[test]
fn encrypt_creates_output_file() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    let out = ws.encrypt(PLAINTEXT);
    assert!(out.status.success(), "exit {:?}", out.status);
    assert!(ws.path("output.rij").exists(), "output file missing");
}

#[test]
fn encrypt_creates_sig_file() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    let out = ws.encrypt(PLAINTEXT);
    assert!(out.status.success());
    assert!(ws.path("output.rij.sig").exists(), ".sig file missing");
}

#[test]
fn encrypt_output_multiple_of_block_size() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    let out = ws.encrypt(PLAINTEXT);
    assert!(out.status.success());
    let ct = ws.read("output.rij");
    assert_eq!(ct.len() % 16, 0, "ciphertext len {} not multiple of 16", ct.len());
}

#[test]
fn encrypt_sig_is_64_bytes() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    let out = ws.encrypt(PLAINTEXT);
    assert!(out.status.success());
    let sig = ws.read("output.rij.sig");
    assert_eq!(sig.len(), 64, "sig len {}, want 64", sig.len());
}

// ---------------------------------------------------------------------------
// Encrypt – PKCS7 padding
// ---------------------------------------------------------------------------

#[test]
fn encrypt_padding_lengths() {
    ensure_built();
    let cases: &[(usize, usize)] = &[
        (0, 16),
        (1, 16),
        (15, 16),
        (16, 32),
        (17, 32),
        (28, 32),
        (31, 32),
        (32, 48),
    ];
    for &(input_len, expected_len) in cases {
        let ws = Workspace::new();
        ws.setup_keys();
        let out = ws.encrypt(&vec![b'A'; input_len]);
        assert!(out.status.success(), "input {input_len}: exit {:?}", out.status);
        let ct = ws.read("output.rij");
        assert_eq!(
            ct.len(),
            expected_len,
            "input {input_len}: got ciphertext len {}, want {expected_len}",
            ct.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Encrypt – HMAC-SHA512 signature correctness
// ---------------------------------------------------------------------------

#[test]
fn encrypt_sig_matches_hmac_sha512() {
    ensure_built();
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    let ws = Workspace::new();
    ws.setup_keys();
    let out = ws.encrypt(PLAINTEXT);
    assert!(out.status.success());

    let key = hex::decode(KEY_HEX).unwrap();
    let ct = ws.read("output.rij");
    let sig = ws.read("output.rij.sig");

    let mut mac = <Hmac<Sha512>>::new_from_slice(&key).unwrap();
    mac.update(&ct);
    let expected = mac.finalize().into_bytes();
    assert_eq!(sig, expected.as_slice(), "sig does not match HMAC-SHA512 of ciphertext");
}

// ---------------------------------------------------------------------------
// Encrypt – determinism and sensitivity
// ---------------------------------------------------------------------------

#[test]
fn encrypt_deterministic_same_key_iv() {
    ensure_built();
    let ws1 = Workspace::new();
    ws1.setup_keys();
    ws1.encrypt(PLAINTEXT);
    let ct1 = ws1.read("output.rij");

    let ws2 = Workspace::new();
    ws2.setup_keys();
    ws2.encrypt(PLAINTEXT);
    let ct2 = ws2.read("output.rij");

    assert_eq!(ct1, ct2, "same key/IV produced different ciphertexts");
}

#[test]
fn encrypt_different_iv_gives_different_ciphertext() {
    ensure_built();
    let ws1 = Workspace::new();
    ws1.setup_keys();
    ws1.encrypt(PLAINTEXT);
    let ct1 = ws1.read("output.rij");

    let ws2 = Workspace::new();
    ws2.write_str("input.key", KEY_HEX);
    ws2.write_str("input.iv", WRONG_IV_HEX);
    ws2.encrypt(PLAINTEXT);
    let ct2 = ws2.read("output.rij");

    assert_ne!(ct1, ct2, "different IV produced same ciphertext");
}

#[test]
fn encrypt_different_key_gives_different_ciphertext() {
    ensure_built();
    let ws1 = Workspace::new();
    ws1.setup_keys();
    ws1.encrypt(PLAINTEXT);
    let ct1 = ws1.read("output.rij");

    let ws2 = Workspace::new();
    ws2.write_str("input.key", WRONG_KEY_HEX);
    ws2.write_str("input.iv", IV_HEX);
    ws2.encrypt(PLAINTEXT);
    let ct2 = ws2.read("output.rij");

    assert_ne!(ct1, ct2, "different key produced same ciphertext");
}

// ---------------------------------------------------------------------------
// Encrypt – stdout messages
// ---------------------------------------------------------------------------

#[test]
fn encrypt_stdout_contains_language_label() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    let out = ws.encrypt(PLAINTEXT);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[ Rust | encrypt ]"),
        "stdout missing language label: {stdout}"
    );
}

#[test]
fn encrypt_stdout_contains_algorithm_name() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    let out = ws.encrypt(PLAINTEXT);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("AES-256/CBC/PKCS7"),
        "stdout missing algorithm name: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// Encrypt – error handling
// ---------------------------------------------------------------------------

#[test]
fn encrypt_exit_one_on_too_few_args() {
    ensure_built();
    let out = Command::new(bin("rijndael-encrypt"))
        .arg("only_one")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn encrypt_exit_one_on_no_args() {
    ensure_built();
    let out = Command::new(bin("rijndael-encrypt")).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn encrypt_nonzero_on_missing_input_file() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    let out = Command::new(bin("rijndael-encrypt"))
        .args([
            ws.path("nonexistent.txt"),
            ws.path("output.rij"),
            ws.path("input.key"),
            ws.path("input.iv"),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "expected non-zero exit");
}

#[test]
fn encrypt_nonzero_on_invalid_key() {
    ensure_built();
    let ws = Workspace::new();
    ws.write_str("short.key", "deadbeef");
    ws.write_str("input.iv", IV_HEX);
    ws.write("input.txt", PLAINTEXT);
    let out = Command::new(bin("rijndael-encrypt"))
        .args([
            ws.path("input.txt"),
            ws.path("output.rij"),
            ws.path("short.key"),
            ws.path("input.iv"),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "expected non-zero exit for invalid key");
}

// ---------------------------------------------------------------------------
// Decrypt – roundtrip
// ---------------------------------------------------------------------------

#[test]
fn decrypt_roundtrip_basic() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    ws.encrypt(PLAINTEXT);
    let out = ws.decrypt();
    assert!(out.status.success(), "decrypt exit {:?}\n{}", out.status,
            String::from_utf8_lossy(&out.stderr));
    let got = ws.read("decrypted.txt");
    assert_eq!(got, PLAINTEXT);
}

#[test]
fn decrypt_roundtrip_empty_input() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    ws.encrypt(b"");
    let out = ws.decrypt();
    assert!(out.status.success());
    let got = ws.read("decrypted.txt");
    assert!(got.is_empty(), "expected empty, got {} bytes", got.len());
}

#[test]
fn decrypt_roundtrip_exact_block() {
    ensure_built();
    let pt = b"1234567890abcdef";
    let ws = Workspace::new();
    ws.setup_keys();
    ws.encrypt(pt);
    let out = ws.decrypt();
    assert!(out.status.success());
    assert_eq!(ws.read("decrypted.txt"), pt);
}

#[test]
fn decrypt_roundtrip_large_input() {
    ensure_built();
    let pt: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
    let ws = Workspace::new();
    ws.setup_keys();
    ws.encrypt(&pt);
    let out = ws.decrypt();
    assert!(out.status.success());
    assert_eq!(ws.read("decrypted.txt"), pt);
}

#[test]
fn decrypt_roundtrip_all_byte_values() {
    ensure_built();
    let pt: Vec<u8> = (0u8..=255).collect();
    let ws = Workspace::new();
    ws.setup_keys();
    ws.encrypt(&pt);
    let out = ws.decrypt();
    assert!(out.status.success());
    assert_eq!(ws.read("decrypted.txt"), pt);
}

// ---------------------------------------------------------------------------
// Decrypt – MAC verification
// ---------------------------------------------------------------------------

#[test]
fn decrypt_mac_verified_in_stdout() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    ws.encrypt(PLAINTEXT);
    let out = ws.decrypt();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("verified OK"),
        "stdout missing MAC verified OK: {stdout}"
    );
}

#[test]
fn decrypt_tampered_ciphertext_fails() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    ws.encrypt(PLAINTEXT);
    let ct_path = ws.path("output.rij");
    let mut ct = fs::read(&ct_path).unwrap();
    ct[0] ^= 0xFF;
    fs::write(&ct_path, &ct).unwrap();
    let out = ws.decrypt();
    assert!(!out.status.success(), "expected non-zero exit on tampered ciphertext");
}

#[test]
fn decrypt_tampered_sig_fails() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    ws.encrypt(PLAINTEXT);
    let sig_path = ws.path("output.rij.sig");
    let mut sig = fs::read(&sig_path).unwrap();
    sig[0] ^= 0xFF;
    fs::write(&sig_path, &sig).unwrap();
    let out = ws.decrypt();
    assert!(!out.status.success(), "expected non-zero exit on tampered sig");
}

#[test]
fn decrypt_missing_sig_issues_warning() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    ws.encrypt(PLAINTEXT);
    fs::remove_file(ws.path("output.rij.sig")).unwrap();
    let out = ws.decrypt();
    assert!(out.status.success(), "Rust decrypt should succeed with warning when .sig missing");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("WARNING"),
        "expected WARNING in stdout when .sig missing: {stdout}"
    );
}

#[test]
fn decrypt_wrong_key_fails_mac() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    ws.encrypt(PLAINTEXT);
    let out = ws.decrypt_with(ws.path("output.rij"), WRONG_KEY_HEX, IV_HEX);
    assert!(!out.status.success(), "expected non-zero exit for wrong key");
}

// ---------------------------------------------------------------------------
// Decrypt – stdout messages
// ---------------------------------------------------------------------------

#[test]
fn decrypt_stdout_contains_language_label() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    ws.encrypt(PLAINTEXT);
    let out = ws.decrypt();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[ Rust | decrypt ]"),
        "stdout missing language label: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// Decrypt – error handling
// ---------------------------------------------------------------------------

#[test]
fn decrypt_exit_one_on_no_args() {
    ensure_built();
    let out = Command::new(bin("rijndael-decrypt")).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn decrypt_nonzero_on_missing_ciphertext_file() {
    ensure_built();
    let ws = Workspace::new();
    ws.setup_keys();
    let out = Command::new(bin("rijndael-decrypt"))
        .args([
            ws.path("nonexistent.rij"),
            ws.path("out.txt"),
            ws.path("input.key"),
            ws.path("input.iv"),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
