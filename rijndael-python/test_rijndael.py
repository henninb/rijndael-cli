#!/usr/bin/env python3
"""Comprehensive tests for the Python Rijndael encrypt/decrypt implementation."""

import hashlib
import hmac as hmac_mod
import os
import subprocess
import sys

import pytest

PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENCRYPT_SCRIPT = os.path.join(PROJECT_ROOT, "rijndael-python", "rijndael-encrypt.py")
DECRYPT_SCRIPT = os.path.join(PROJECT_ROOT, "rijndael-python", "rijndael-decrypt.py")

KEY_HEX       = "594193e330c8e8312f244c9cff045b73e66c301c30eb3bf0ec943a25e7a45650"
IV_HEX        = "2cef85f5259ae311034de17fda3b8369"
PLAINTEXT     = b"my message to you, let's win"   # 28 bytes
WRONG_KEY_HEX = "0000000000000000000000000000000000000000000000000000000000000000"
WRONG_IV_HEX  = "ffffffffffffffffffffffffffffffff"


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "input.key").write_text(KEY_HEX)
    (tmp_path / "input.iv").write_text(IV_HEX)
    return tmp_path


def encrypt(workspace, plaintext=None, key_hex=None, iv_hex=None):
    if plaintext is None:
        plaintext = PLAINTEXT
    if key_hex is not None:
        (workspace / "input.key").write_text(key_hex)
    if iv_hex is not None:
        (workspace / "input.iv").write_text(iv_hex)
    inp = workspace / "input.txt"
    out = workspace / "output.rij"
    inp.write_bytes(plaintext)
    result = subprocess.run(
        [sys.executable, ENCRYPT_SCRIPT,
         str(inp), str(out),
         str(workspace / "input.key"), str(workspace / "input.iv")],
        capture_output=True, text=True,
    )
    return result, out


def decrypt(workspace, ciphertext_path=None, out_name="decrypted.txt",
            key_hex=None, iv_hex=None):
    if key_hex is not None:
        (workspace / "input.key").write_text(key_hex)
    if iv_hex is not None:
        (workspace / "input.iv").write_text(iv_hex)
    if ciphertext_path is None:
        ciphertext_path = workspace / "output.rij"
    out = workspace / out_name
    result = subprocess.run(
        [sys.executable, DECRYPT_SCRIPT,
         str(ciphertext_path), str(out),
         str(workspace / "input.key"), str(workspace / "input.iv")],
        capture_output=True, text=True,
    )
    return result, out


# ---------------------------------------------------------------------------
# Encrypt – output structure
# ---------------------------------------------------------------------------

class TestEncryptOutput:
    def test_creates_ciphertext_file(self, workspace):
        result, out = encrypt(workspace)
        assert result.returncode == 0
        assert out.exists()

    def test_creates_sig_file(self, workspace):
        result, out = encrypt(workspace)
        assert result.returncode == 0
        assert (workspace / "output.rij.sig").exists()

    def test_ciphertext_multiple_of_block_size(self, workspace):
        result, out = encrypt(workspace)
        assert result.returncode == 0
        assert len(out.read_bytes()) % 16 == 0

    def test_sig_is_64_bytes(self, workspace):
        result, out = encrypt(workspace)
        assert result.returncode == 0
        assert len((workspace / "output.rij.sig").read_bytes()) == 64


# ---------------------------------------------------------------------------
# Encrypt – PKCS7 padding lengths
# ---------------------------------------------------------------------------

class TestEncryptPadding:
    @pytest.mark.parametrize("input_len,expected_output_len", [
        (0,  16),   # empty  -> 1 full padding block
        (1,  16),
        (15, 16),   # just under one block
        (16, 32),   # exactly one block -> extra block appended
        (17, 32),
        (27, 32),
        (28, 32),   # default test vector
        (31, 32),
        (32, 48),   # exactly two blocks -> third block appended
    ])
    def test_padded_output_length(self, workspace, input_len, expected_output_len):
        result, out = encrypt(workspace, plaintext=b"X" * input_len)
        assert result.returncode == 0
        assert len(out.read_bytes()) == expected_output_len


# ---------------------------------------------------------------------------
# Encrypt – HMAC-SHA512 signature correctness
# ---------------------------------------------------------------------------

class TestEncryptSignature:
    def test_sig_matches_hmac_sha512_of_ciphertext(self, workspace):
        result, out = encrypt(workspace)
        assert result.returncode == 0
        key = bytes.fromhex(KEY_HEX)
        ciphertext = out.read_bytes()
        expected = hmac_mod.new(key, ciphertext, hashlib.sha512).digest()
        assert (workspace / "output.rij.sig").read_bytes() == expected

    def test_different_key_produces_different_sig(self, workspace):
        result, out = encrypt(workspace)
        sig1 = (workspace / "output.rij.sig").read_bytes()

        ws2 = workspace / "b"
        ws2.mkdir()
        (ws2 / "input.key").write_text(WRONG_KEY_HEX)
        (ws2 / "input.iv").write_text(IV_HEX)
        result2, out2 = encrypt(ws2)
        sig2 = (ws2 / "output.rij.sig").read_bytes()
        assert sig1 != sig2


# ---------------------------------------------------------------------------
# Encrypt – determinism and key/IV sensitivity
# ---------------------------------------------------------------------------

class TestEncryptDeterminism:
    def test_same_key_iv_gives_same_ciphertext(self, workspace, tmp_path):
        result1, out1 = encrypt(workspace)
        ws2 = tmp_path / "run2"
        ws2.mkdir()
        (ws2 / "input.key").write_text(KEY_HEX)
        (ws2 / "input.iv").write_text(IV_HEX)
        result2, out2 = encrypt(ws2)
        assert out1.read_bytes() == out2.read_bytes()

    def test_different_iv_gives_different_ciphertext(self, workspace, tmp_path):
        result1, out1 = encrypt(workspace)
        ct1 = out1.read_bytes()
        ws2 = tmp_path / "run2"
        ws2.mkdir()
        (ws2 / "input.key").write_text(KEY_HEX)
        (ws2 / "input.iv").write_text(WRONG_IV_HEX)
        result2, out2 = encrypt(ws2)
        assert ct1 != out2.read_bytes()

    def test_different_key_gives_different_ciphertext(self, workspace, tmp_path):
        result1, out1 = encrypt(workspace)
        ct1 = out1.read_bytes()
        ws2 = tmp_path / "run2"
        ws2.mkdir()
        (ws2 / "input.key").write_text(WRONG_KEY_HEX)
        (ws2 / "input.iv").write_text(IV_HEX)
        result2, out2 = encrypt(ws2)
        assert ct1 != out2.read_bytes()


# ---------------------------------------------------------------------------
# Encrypt – stdout / stderr
# ---------------------------------------------------------------------------

class TestEncryptOutput_Messages:
    def test_stdout_contains_language_label(self, workspace):
        result, _ = encrypt(workspace)
        assert "[ Python | encrypt ]" in result.stdout

    def test_stdout_contains_algorithm_name(self, workspace):
        result, _ = encrypt(workspace)
        assert "AES-256/CBC/PKCS7" in result.stdout

    def test_stdout_reports_byte_counts(self, workspace):
        result, _ = encrypt(workspace)
        assert "28 bytes" in result.stdout   # original length
        assert "32 bytes" in result.stdout   # padded length

    def test_stdout_reports_signature_written(self, workspace):
        result, _ = encrypt(workspace)
        assert "signature" in result.stdout.lower()


# ---------------------------------------------------------------------------
# Encrypt – error handling
# ---------------------------------------------------------------------------

class TestEncryptErrors:
    def test_exit_1_on_too_few_args(self):
        r = subprocess.run([sys.executable, ENCRYPT_SCRIPT, "a", "b"],
                           capture_output=True)
        assert r.returncode == 1

    def test_exit_1_on_no_args(self):
        r = subprocess.run([sys.executable, ENCRYPT_SCRIPT],
                           capture_output=True)
        assert r.returncode == 1

    def test_nonzero_on_missing_input_file(self, workspace):
        result = subprocess.run(
            [sys.executable, ENCRYPT_SCRIPT,
             str(workspace / "nonexistent.txt"),
             str(workspace / "output.rij"),
             str(workspace / "input.key"),
             str(workspace / "input.iv")],
            capture_output=True,
        )
        assert result.returncode != 0

    def test_nonzero_on_missing_key_file(self, workspace):
        (workspace / "input.txt").write_bytes(PLAINTEXT)
        result = subprocess.run(
            [sys.executable, ENCRYPT_SCRIPT,
             str(workspace / "input.txt"),
             str(workspace / "output.rij"),
             str(workspace / "nokey.key"),
             str(workspace / "input.iv")],
            capture_output=True,
        )
        assert result.returncode != 0


# ---------------------------------------------------------------------------
# Decrypt – roundtrip
# ---------------------------------------------------------------------------

class TestDecryptRoundtrip:
    def test_basic_roundtrip(self, workspace):
        result, _ = encrypt(workspace)
        assert result.returncode == 0
        dec_result, dec_file = decrypt(workspace)
        assert dec_result.returncode == 0
        assert dec_file.read_bytes() == PLAINTEXT

    def test_roundtrip_empty_input(self, workspace):
        encrypt(workspace, plaintext=b"")
        dec_result, dec_file = decrypt(workspace)
        assert dec_result.returncode == 0
        assert dec_file.read_bytes() == b""

    def test_roundtrip_exactly_one_block(self, workspace):
        pt = b"1234567890abcdef"
        encrypt(workspace, plaintext=pt)
        dec_result, dec_file = decrypt(workspace)
        assert dec_result.returncode == 0
        assert dec_file.read_bytes() == pt

    def test_roundtrip_large_input(self, workspace):
        pt = b"A" * 4096 + b"B" * 4095
        encrypt(workspace, plaintext=pt)
        dec_result, dec_file = decrypt(workspace)
        assert dec_result.returncode == 0
        assert dec_file.read_bytes() == pt

    def test_roundtrip_binary_data(self, workspace):
        pt = bytes(range(256)) * 4
        encrypt(workspace, plaintext=pt)
        dec_result, dec_file = decrypt(workspace)
        assert dec_result.returncode == 0
        assert dec_file.read_bytes() == pt


# ---------------------------------------------------------------------------
# Decrypt – MAC verification
# ---------------------------------------------------------------------------

class TestDecryptMAC:
    def test_mac_verified_ok_in_stdout(self, workspace):
        encrypt(workspace)
        dec_result, _ = decrypt(workspace)
        assert dec_result.returncode == 0
        assert "verified OK" in dec_result.stdout

    def test_tampered_ciphertext_causes_mac_failure(self, workspace):
        result, out = encrypt(workspace)
        assert result.returncode == 0
        data = bytearray(out.read_bytes())
        data[0] ^= 0xFF
        out.write_bytes(bytes(data))
        dec_result, _ = decrypt(workspace)
        assert dec_result.returncode != 0

    def test_tampered_sig_causes_mac_failure(self, workspace):
        encrypt(workspace)
        sig_file = workspace / "output.rij.sig"
        sig_data = bytearray(sig_file.read_bytes())
        sig_data[0] ^= 0xFF
        sig_file.write_bytes(bytes(sig_data))
        dec_result, _ = decrypt(workspace)
        assert dec_result.returncode != 0

    def test_missing_sig_file_aborts_with_exit_1(self, workspace):
        encrypt(workspace)
        (workspace / "output.rij.sig").unlink()
        dec_result, _ = decrypt(workspace)
        assert dec_result.returncode == 1

    def test_wrong_key_causes_mac_failure(self, workspace):
        encrypt(workspace)
        dec_result, _ = decrypt(workspace, key_hex=WRONG_KEY_HEX)
        assert dec_result.returncode != 0


# ---------------------------------------------------------------------------
# Decrypt – stdout / stderr
# ---------------------------------------------------------------------------

class TestDecryptMessages:
    def test_stdout_contains_language_label(self, workspace):
        encrypt(workspace)
        dec_result, _ = decrypt(workspace)
        assert "[ Python | decrypt ]" in dec_result.stdout

    def test_stdout_contains_algorithm_name(self, workspace):
        encrypt(workspace)
        dec_result, _ = decrypt(workspace)
        assert "AES-256/CBC/PKCS7" in dec_result.stdout

    def test_stdout_reports_output_file(self, workspace):
        encrypt(workspace)
        dec_result, dec_file = decrypt(workspace)
        assert str(dec_file) in dec_result.stdout


# ---------------------------------------------------------------------------
# Decrypt – error handling
# ---------------------------------------------------------------------------

class TestDecryptErrors:
    def test_exit_1_on_too_few_args(self):
        r = subprocess.run([sys.executable, DECRYPT_SCRIPT, "a"],
                           capture_output=True)
        assert r.returncode == 1

    def test_exit_1_on_no_args(self):
        r = subprocess.run([sys.executable, DECRYPT_SCRIPT],
                           capture_output=True)
        assert r.returncode == 1

    def test_nonzero_on_missing_input_file(self, workspace):
        result = subprocess.run(
            [sys.executable, DECRYPT_SCRIPT,
             str(workspace / "nonexistent.rij"),
             str(workspace / "out.txt"),
             str(workspace / "input.key"),
             str(workspace / "input.iv")],
            capture_output=True,
        )
        assert result.returncode != 0
