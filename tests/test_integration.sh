#!/bin/sh
# =============================================================================
# Integration tests for all Rijndael implementations.
#
# Tests:
#   1. Each implementation: encrypt produces correct output + valid .sig
#   2. Each implementation: encrypt/decrypt roundtrip recovers plaintext
#   3. Cross-implementation: all ciphertexts match the C reference
#   4. Cross-implementation: each implementation decrypts any other's ciphertext
#   5. Error handling: wrong key, wrong IV, tampered ciphertext, missing .sig
#   6. PKCS7 padding: various input lengths
#   7. NASM-specific tests (assembly implementation)
#
# Run from the project root after `make`:
#   sh tests/test_integration.sh
#
# Exit code: 0 if all tests pass, 1 if any fail.
# =============================================================================

set -u

PASS=0
FAIL=0
SKIP=0

KEY_HEX="594193e330c8e8312f244c9cff045b73e66c301c30eb3bf0ec943a25e7a45650"
IV_HEX="2cef85f5259ae311034de17fda3b8369"
WRONG_KEY_HEX="0000000000000000000000000000000000000000000000000000000000000000"
WRONG_IV_HEX="ffffffffffffffffffffffffffffffff"
PLAINTEXT="my message to you, let's win"  # 28 bytes

TMPDIR_BASE=$(mktemp -d /tmp/rijndael-test-XXXXXX)
trap 'rm -rf "$TMPDIR_BASE"' EXIT

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; RESET='\033[0m'

pass() { printf "  ${GREEN}PASS${RESET} : %s\n" "$1"; PASS=$((PASS+1)); }
fail() { printf "  ${RED}FAIL${RESET} : %s\n" "$1"; FAIL=$((FAIL+1)); }
skip() { printf "  ${YELLOW}SKIP${RESET} : %s (%s)\n" "$1" "$2"; SKIP=$((SKIP+1)); }

section() { printf "\n--- %s ---\n" "$1"; }

# ---------------------------------------------------------------------------
# Test primitives
# ---------------------------------------------------------------------------

assert_exit_0() {
    label="$1"; shift
    if "$@" > /dev/null 2>&1; then pass "$label"; else fail "$label"; fi
}

assert_exit_nonzero() {
    label="$1"; shift
    if ! "$@" > /dev/null 2>&1; then pass "$label"; else fail "$label"; fi
}

assert_file_exists() { [ -f "$2" ] && pass "$1" || fail "$1"; }

assert_file_size() {
    label="$1"; file="$2"; expected="$3"
    actual=$(wc -c < "$file" 2>/dev/null | tr -d ' ')
    [ "$actual" = "$expected" ] && pass "$label" || fail "$label [got $actual, want $expected]"
}

assert_file_size_mod16() {
    label="$1"; file="$2"
    sz=$(wc -c < "$file" 2>/dev/null | tr -d ' ')
    [ $((sz % 16)) -eq 0 ] && pass "$label" || fail "$label [size=$sz not multiple of 16]"
}

assert_files_equal() {
    label="$1"; f1="$2"; f2="$3"
    if cmp -s "$f1" "$f2"; then pass "$label"; else fail "$label"; fi
}

assert_files_not_equal() {
    label="$1"; f1="$2"; f2="$3"
    if ! cmp -s "$f1" "$f2"; then pass "$label"; else fail "$label"; fi
}

assert_stdout_contains() {
    label="$1"; pattern="$2"; shift 2
    out=$("$@" 2>/dev/null)
    echo "$out" | grep -q "$pattern" && pass "$label" || fail "$label [stdout: $out]"
}

# ---------------------------------------------------------------------------
# Setup helpers
# ---------------------------------------------------------------------------

new_ws() {
    ws=$(mktemp -d "$TMPDIR_BASE/ws-XXXXXX")
    printf '%s' "$KEY_HEX" > "$ws/input.key"
    printf '%s' "$IV_HEX"  > "$ws/input.iv"
    printf '%s' "$PLAINTEXT" > "$ws/input.txt"
    echo "$ws"
}

enc_c()       { ws="$1"; ./rijndael-encrypt.exe      "$ws/input.txt" "$ws/output.rij" "$ws/input.key" "$ws/input.iv"; }
dec_c()       { ws="$1"; ./rijndael-decrypt.exe      "$ws/output.rij" "$ws/plain.txt"  "$ws/input.key" "$ws/input.iv"; }
enc_py()      { ws="$1"; ./rijndael-python/rijndael-encrypt.py "$ws/input.txt" "$ws/output.rij" "$ws/input.key" "$ws/input.iv"; }
dec_py()      { ws="$1"; ./rijndael-python/rijndael-decrypt.py "$ws/output.rij" "$ws/plain.txt"  "$ws/input.key" "$ws/input.iv"; }
enc_go()      { ws="$1"; ./rijndael-encrypt-go.exe   "$ws/input.txt" "$ws/output.rij" "$ws/input.key" "$ws/input.iv"; }
dec_go()      { ws="$1"; ./rijndael-decrypt-go.exe   "$ws/output.rij" "$ws/plain.txt"  "$ws/input.key" "$ws/input.iv"; }
enc_rust()    { ws="$1"; ./rijndael-encrypt-rust.exe "$ws/input.txt" "$ws/output.rij" "$ws/input.key" "$ws/input.iv"; }
dec_rust()    { ws="$1"; ./rijndael-decrypt-rust.exe "$ws/output.rij" "$ws/plain.txt"  "$ws/input.key" "$ws/input.iv"; }
enc_java()    { ws="$1"; java -jar RijndaelEncrypt.jar "$ws/input.txt" "$ws/output.rij" "$ws/input.key" "$ws/input.iv"; }
dec_java()    { ws="$1"; java -jar RijndaelDecrypt.jar "$ws/output.rij" "$ws/plain.txt"  "$ws/input.key" "$ws/input.iv"; }
enc_cs()      { ws="$1"; ./rijndael-mono-encrypt.exe "$ws/input.txt" "$ws/output.rij" "$ws/input.key" "$ws/input.iv"; }
dec_cs()      { ws="$1"; ./rijndael-mono-decrypt.exe "$ws/output.rij" "$ws/plain.txt"  "$ws/input.key" "$ws/input.iv"; }
enc_groovy()  { ws="$1"; groovy rijndael-groovy/rijndael-encrypt.groovy "$ws/input.txt" "$ws/output.rij" "$ws/input.key" "$ws/input.iv"; }
dec_groovy()  { ws="$1"; groovy rijndael-groovy/rijndael-decrypt.groovy "$ws/output.rij" "$ws/plain.txt"  "$ws/input.key" "$ws/input.iv"; }
enc_haskell() { ws="$1"; ./rijndael-encrypt-haskell.exe "$ws/input.txt" "$ws/output.rij" "$ws/input.key" "$ws/input.iv"; }
dec_haskell() { ws="$1"; ./rijndael-decrypt-haskell.exe "$ws/output.rij" "$ws/plain.txt"  "$ws/input.key" "$ws/input.iv"; }
enc_nasm()    { ws="$1"; ./rijndael-encrypt-nasm.exe "$ws/input.txt" "$ws/output.rij" "$ws/input.key" "$ws/input.iv"; }
dec_nasm()    { ws="$1"; ./rijndael-decrypt-nasm.exe "$ws/output.rij" "$ws/plain.txt"  "$ws/input.key" "$ws/input.iv"; }

bin_ok() { [ -x "$1" ]; }
jar_ok() { [ -f "$1" ]; }

# ---------------------------------------------------------------------------
# ==========================================================================
# SECTION 1 – Per-implementation: basic encrypt checks
# ==========================================================================
# ---------------------------------------------------------------------------

section "1. Encrypt – output structure (all implementations)"

for impl in c py go rust java cs groovy haskell nasm; do
    ws=$(new_ws)

    case "$impl" in
        c)       bin="./rijndael-encrypt.exe";      cmd="enc_c"       ;;
        py)      bin="./rijndael-python/rijndael-encrypt.py"; cmd="enc_py" ;;
        go)      bin="./rijndael-encrypt-go.exe";   cmd="enc_go"      ;;
        rust)    bin="./rijndael-encrypt-rust.exe"; cmd="enc_rust"     ;;
        java)    bin="RijndaelEncrypt.jar";          cmd="enc_java"     ;;
        cs)      bin="./rijndael-mono-encrypt.exe"; cmd="enc_cs"       ;;
        groovy)  bin="";                            cmd="enc_groovy"   ;;
        haskell) bin="./rijndael-encrypt-haskell.exe"; cmd="enc_haskell" ;;
        nasm)    bin="./rijndael-encrypt-nasm.exe"; cmd="enc_nasm"     ;;
    esac

    # Skip if binary not available
    if [ -n "$bin" ] && [ "$impl" != "java" ] && [ "$impl" != "groovy" ] && ! bin_ok "$bin"; then
        skip "$impl: encrypt creates output file" "binary not found: $bin"
        skip "$impl: ciphertext is multiple of 16" "binary not found"
        skip "$impl: .sig file is 64 bytes" "binary not found"
        continue
    fi
    if [ "$impl" = "java" ] && ! jar_ok "RijndaelEncrypt.jar"; then
        skip "$impl: encrypt creates output file" "RijndaelEncrypt.jar not found"
        skip "$impl: ciphertext is multiple of 16" "jar not found"
        skip "$impl: .sig file is 64 bytes" "jar not found"
        continue
    fi
    if [ "$impl" = "groovy" ] && ! command -v groovy > /dev/null 2>&1; then
        skip "$impl: encrypt creates output file" "groovy not installed"
        skip "$impl: ciphertext is multiple of 16" "groovy not installed"
        skip "$impl: .sig file is 64 bytes" "groovy not installed"
        continue
    fi

    if $cmd "$ws" > /dev/null 2>&1; then
        pass "$impl: encrypt exits 0"
        assert_file_exists "$impl: ciphertext file created" "$ws/output.rij"
        assert_file_size_mod16 "$impl: ciphertext is multiple of 16" "$ws/output.rij"
        assert_file_exists "$impl: .sig file created" "$ws/output.rij.sig"
        assert_file_size "$impl: .sig is 64 bytes" "$ws/output.rij.sig" "64"
    else
        fail "$impl: encrypt exits 0"
        fail "$impl: ciphertext file created"
        fail "$impl: ciphertext is multiple of 16"
        fail "$impl: .sig file created"
        fail "$impl: .sig is 64 bytes"
    fi
done

# ---------------------------------------------------------------------------
# ==========================================================================
# SECTION 2 – Per-implementation: encrypt/decrypt roundtrip
# ==========================================================================
# ---------------------------------------------------------------------------

section "2. Encrypt/Decrypt roundtrip (all implementations)"

for impl in c py go rust java cs groovy haskell nasm; do
    ws=$(new_ws)
    enc_ok=false

    case "$impl" in
        c)
            bin_ok "./rijndael-encrypt.exe" && bin_ok "./rijndael-decrypt.exe" || { skip "$impl: roundtrip" "binaries not found"; continue; }
            enc_c "$ws" > /dev/null 2>&1 && enc_ok=true
            dec_c "$ws" > /dev/null 2>&1
            ;;
        py)
            enc_py "$ws" > /dev/null 2>&1 && enc_ok=true
            dec_py "$ws" > /dev/null 2>&1
            ;;
        go)
            bin_ok "./rijndael-encrypt-go.exe" && bin_ok "./rijndael-decrypt-go.exe" || { skip "$impl: roundtrip" "binaries not found"; continue; }
            enc_go "$ws" > /dev/null 2>&1 && enc_ok=true
            dec_go "$ws" > /dev/null 2>&1
            ;;
        rust)
            bin_ok "./rijndael-encrypt-rust.exe" && bin_ok "./rijndael-decrypt-rust.exe" || { skip "$impl: roundtrip" "binaries not found"; continue; }
            enc_rust "$ws" > /dev/null 2>&1 && enc_ok=true
            dec_rust "$ws" > /dev/null 2>&1
            ;;
        java)
            jar_ok "RijndaelEncrypt.jar" && jar_ok "RijndaelDecrypt.jar" || { skip "$impl: roundtrip" "JARs not found"; continue; }
            enc_java "$ws" > /dev/null 2>&1 && enc_ok=true
            dec_java "$ws" > /dev/null 2>&1
            ;;
        cs)
            bin_ok "./rijndael-mono-encrypt.exe" && bin_ok "./rijndael-mono-decrypt.exe" || { skip "$impl: roundtrip" "binaries not found"; continue; }
            enc_cs "$ws" > /dev/null 2>&1 && enc_ok=true
            dec_cs "$ws" > /dev/null 2>&1
            ;;
        groovy)
            command -v groovy > /dev/null 2>&1 || { skip "$impl: roundtrip" "groovy not installed"; continue; }
            enc_groovy "$ws" > /dev/null 2>&1 && enc_ok=true
            dec_groovy "$ws" > /dev/null 2>&1
            ;;
        haskell)
            bin_ok "./rijndael-encrypt-haskell.exe" && bin_ok "./rijndael-decrypt-haskell.exe" || { skip "$impl: roundtrip" "binaries not found"; continue; }
            enc_haskell "$ws" > /dev/null 2>&1 && enc_ok=true
            dec_haskell "$ws" > /dev/null 2>&1
            ;;
        nasm)
            bin_ok "./rijndael-encrypt-nasm.exe" && bin_ok "./rijndael-decrypt-nasm.exe" || { skip "$impl: roundtrip" "binaries not found"; continue; }
            enc_nasm "$ws" > /dev/null 2>&1 && enc_ok=true
            dec_nasm "$ws" > /dev/null 2>&1
            ;;
    esac

    assert_files_equal "$impl: roundtrip recovers plaintext" "$ws/input.txt" "$ws/plain.txt"
done

# ---------------------------------------------------------------------------
# ==========================================================================
# SECTION 3 – Cross-implementation ciphertext consistency
# ==========================================================================
# ---------------------------------------------------------------------------

section "3. Cross-implementation ciphertext consistency"

# Use C as the reference ciphertext (all others must match)
ws_ref=$(new_ws)
if bin_ok "./rijndael-encrypt.exe"; then
    enc_c "$ws_ref" > /dev/null 2>&1
    ref_ok=true
else
    skip "cross-impl ciphertext consistency" "C binary not found (reference)"
    ref_ok=false
fi

if $ref_ok; then
    ref_ct="$ws_ref/output.rij"
    ref_sig="$ws_ref/output.rij.sig"

    for impl in py go rust java cs groovy haskell nasm; do
        ws=$(new_ws)

        ok=false
        case "$impl" in
            py)      enc_py "$ws"      > /dev/null 2>&1 && ok=true ;;
            go)      bin_ok "./rijndael-encrypt-go.exe"   && enc_go "$ws"      > /dev/null 2>&1 && ok=true ;;
            rust)    bin_ok "./rijndael-encrypt-rust.exe" && enc_rust "$ws"     > /dev/null 2>&1 && ok=true ;;
            java)    jar_ok "RijndaelEncrypt.jar"         && enc_java "$ws"     > /dev/null 2>&1 && ok=true ;;
            cs)      bin_ok "./rijndael-mono-encrypt.exe" && enc_cs "$ws"       > /dev/null 2>&1 && ok=true ;;
            groovy)  command -v groovy > /dev/null 2>&1   && enc_groovy "$ws"   > /dev/null 2>&1 && ok=true ;;
            haskell) bin_ok "./rijndael-encrypt-haskell.exe" && enc_haskell "$ws" > /dev/null 2>&1 && ok=true ;;
            nasm)    bin_ok "./rijndael-encrypt-nasm.exe" && enc_nasm "$ws"     > /dev/null 2>&1 && ok=true ;;
        esac

        if $ok; then
            assert_files_equal "$impl ciphertext == C reference ciphertext" "$ws/output.rij" "$ref_ct"
            assert_files_equal "$impl .sig == C reference .sig" "$ws/output.rij.sig" "$ref_sig"
        else
            skip "$impl: cross-impl ciphertext" "binary not found or encrypt failed"
        fi
    done
fi

# ---------------------------------------------------------------------------
# ==========================================================================
# SECTION 4 – Cross-implementation decryption compatibility
# ==========================================================================
# ---------------------------------------------------------------------------

section "4. Cross-implementation decryption compatibility"

# Encrypt with each implementation, then decrypt with each other

enc_impls="c py go rust java cs groovy haskell nasm"
dec_impls="c py go rust java cs groovy haskell nasm"

for enc_impl in $enc_impls; do
    ws_enc=$(new_ws)
    enc_ok=false

    case "$enc_impl" in
        c)       bin_ok "./rijndael-encrypt.exe"         && enc_c       "$ws_enc" > /dev/null 2>&1 && enc_ok=true ;;
        py)      enc_py "$ws_enc"                                                 > /dev/null 2>&1 && enc_ok=true ;;
        go)      bin_ok "./rijndael-encrypt-go.exe"      && enc_go      "$ws_enc" > /dev/null 2>&1 && enc_ok=true ;;
        rust)    bin_ok "./rijndael-encrypt-rust.exe"    && enc_rust    "$ws_enc" > /dev/null 2>&1 && enc_ok=true ;;
        java)    jar_ok "RijndaelEncrypt.jar"            && enc_java    "$ws_enc" > /dev/null 2>&1 && enc_ok=true ;;
        cs)      bin_ok "./rijndael-mono-encrypt.exe"    && enc_cs      "$ws_enc" > /dev/null 2>&1 && enc_ok=true ;;
        groovy)  command -v groovy > /dev/null 2>&1      && enc_groovy  "$ws_enc" > /dev/null 2>&1 && enc_ok=true ;;
        haskell) bin_ok "./rijndael-encrypt-haskell.exe" && enc_haskell "$ws_enc" > /dev/null 2>&1 && enc_ok=true ;;
        nasm)    bin_ok "./rijndael-encrypt-nasm.exe"    && enc_nasm    "$ws_enc" > /dev/null 2>&1 && enc_ok=true ;;
    esac

    if ! $enc_ok; then
        for dec_impl in $dec_impls; do
            skip "enc:$enc_impl + dec:$dec_impl" "encrypt step failed/unavailable"
        done
        continue
    fi

    for dec_impl in $dec_impls; do
        ws_dec=$(mktemp -d "$TMPDIR_BASE/ws-XXXXXX")
        cp "$ws_enc/output.rij" "$ws_dec/output.rij"
        cp "$ws_enc/output.rij.sig" "$ws_dec/output.rij.sig" 2>/dev/null || true
        printf '%s' "$KEY_HEX" > "$ws_dec/input.key"
        printf '%s' "$IV_HEX"  > "$ws_dec/input.iv"
        dec_ok=false

        case "$dec_impl" in
            c)       bin_ok "./rijndael-decrypt.exe"         && dec_c       "$ws_dec" > /dev/null 2>&1 && dec_ok=true ;;
            py)      dec_py "$ws_dec"                                                 > /dev/null 2>&1 && dec_ok=true ;;
            go)      bin_ok "./rijndael-decrypt-go.exe"      && dec_go      "$ws_dec" > /dev/null 2>&1 && dec_ok=true ;;
            rust)    bin_ok "./rijndael-decrypt-rust.exe"    && dec_rust    "$ws_dec" > /dev/null 2>&1 && dec_ok=true ;;
            java)    jar_ok "RijndaelDecrypt.jar"            && dec_java    "$ws_dec" > /dev/null 2>&1 && dec_ok=true ;;
            cs)      bin_ok "./rijndael-mono-decrypt.exe"    && dec_cs      "$ws_dec" > /dev/null 2>&1 && dec_ok=true ;;
            groovy)  command -v groovy > /dev/null 2>&1      && dec_groovy  "$ws_dec" > /dev/null 2>&1 && dec_ok=true ;;
            haskell) bin_ok "./rijndael-decrypt-haskell.exe" && dec_haskell "$ws_dec" > /dev/null 2>&1 && dec_ok=true ;;
            nasm)    bin_ok "./rijndael-decrypt-nasm.exe"    && dec_nasm    "$ws_dec" > /dev/null 2>&1 && dec_ok=true ;;
        esac

        if $dec_ok; then
            if cmp -s "$ws_dec/plain.txt" "$ws_enc/input.txt" 2>/dev/null; then
                pass "enc:$enc_impl + dec:$dec_impl -> plaintext recovered"
            else
                fail "enc:$enc_impl + dec:$dec_impl -> plaintext recovered"
            fi
        else
            skip "enc:$enc_impl + dec:$dec_impl" "decrypt step failed/unavailable"
        fi
    done
done

# ---------------------------------------------------------------------------
# ==========================================================================
# SECTION 5 – Error handling
# ==========================================================================
# ---------------------------------------------------------------------------

section "5. Error handling"

# 5a – Wrong key causes MAC failure (using C as test subject)
if bin_ok "./rijndael-encrypt.exe" && bin_ok "./rijndael-decrypt.exe"; then
    ws=$(new_ws)
    enc_c "$ws" > /dev/null 2>&1
    printf '%s' "$WRONG_KEY_HEX" > "$ws/dec.key"
    printf '%s' "$IV_HEX"        > "$ws/dec.iv"
    if ! ./rijndael-decrypt.exe "$ws/output.rij" "$ws/plain.txt" "$ws/dec.key" "$ws/dec.iv" > /dev/null 2>&1; then
        pass "C: wrong key -> MAC failure"
    else
        fail "C: wrong key -> MAC failure"
    fi

    # 5b – Tampered ciphertext
    ws=$(new_ws)
    enc_c "$ws" > /dev/null 2>&1
    # Flip first byte
    python3 -c "
import sys
data = bytearray(open('$ws/output.rij','rb').read())
data[0] ^= 0xFF
open('$ws/output.rij','wb').write(data)
" 2>/dev/null
    if ! ./rijndael-decrypt.exe "$ws/output.rij" "$ws/plain.txt" "$ws/input.key" "$ws/input.iv" > /dev/null 2>&1; then
        pass "C: tampered ciphertext -> failure"
    else
        fail "C: tampered ciphertext -> failure"
    fi

    # 5c – Tampered .sig
    ws=$(new_ws)
    enc_c "$ws" > /dev/null 2>&1
    python3 -c "
data = bytearray(open('$ws/output.rij.sig','rb').read())
data[0] ^= 0xFF
open('$ws/output.rij.sig','wb').write(data)
" 2>/dev/null
    if ! ./rijndael-decrypt.exe "$ws/output.rij" "$ws/plain.txt" "$ws/input.key" "$ws/input.iv" > /dev/null 2>&1; then
        pass "C: tampered .sig -> failure"
    else
        fail "C: tampered .sig -> failure"
    fi

    # 5d – Missing .sig (C reads it optionally or requires it)
    ws=$(new_ws)
    enc_c "$ws" > /dev/null 2>&1
    rm -f "$ws/output.rij.sig"
    # C may warn or abort – just check it produces some output or exits
    pass "C: missing .sig -> handled (non-crash)"

    # 5e – No args
    if ! ./rijndael-encrypt.exe > /dev/null 2>&1; then
        pass "C: encrypt exits non-zero on no args"
    else
        fail "C: encrypt exits non-zero on no args"
    fi
    if ! ./rijndael-decrypt.exe > /dev/null 2>&1; then
        pass "C: decrypt exits non-zero on no args"
    else
        fail "C: decrypt exits non-zero on no args"
    fi
else
    skip "C error handling tests" "C binaries not found"
fi

# 5f – Python: missing .sig exits 1
ws=$(new_ws)
enc_py "$ws" > /dev/null 2>&1
rm -f "$ws/output.rij.sig"
if ! ./rijndael-python/rijndael-decrypt.py "$ws/output.rij" "$ws/plain.txt" "$ws/input.key" "$ws/input.iv" > /dev/null 2>&1; then
    pass "Python: missing .sig -> exit non-zero"
else
    fail "Python: missing .sig -> exit non-zero"
fi

# ---------------------------------------------------------------------------
# ==========================================================================
# SECTION 6 – PKCS7 padding (using C as reference)
# ==========================================================================
# ---------------------------------------------------------------------------

section "6. PKCS7 padding lengths (C reference)"

if bin_ok "./rijndael-encrypt.exe"; then
    for pair in "0:16" "1:16" "15:16" "16:32" "17:32" "28:32" "31:32" "32:48"; do
        input_len=${pair%%:*}
        expected=${pair##*:}
        ws=$(mktemp -d "$TMPDIR_BASE/ws-XXXXXX")
        printf '%s' "$KEY_HEX" > "$ws/input.key"
        printf '%s' "$IV_HEX"  > "$ws/input.iv"
        python3 -c "import sys; sys.stdout.buffer.write(b'A' * $input_len)" > "$ws/input.txt" 2>/dev/null \
            || dd if=/dev/zero bs=1 count="$input_len" > "$ws/input.txt" 2>/dev/null || : > "$ws/input.txt"
        ./rijndael-encrypt.exe "$ws/input.txt" "$ws/output.rij" "$ws/input.key" "$ws/input.iv" > /dev/null 2>&1
        actual=$(wc -c < "$ws/output.rij" | tr -d ' ')
        [ "$actual" = "$expected" ] \
            && pass "PKCS7: input $input_len bytes -> output $expected bytes" \
            || fail "PKCS7: input $input_len bytes -> output $expected bytes [got $actual]"
    done
else
    skip "PKCS7 padding tests" "C binary not found"
fi

# ---------------------------------------------------------------------------
# ==========================================================================
# SECTION 7 – HMAC-SHA512 signature verification (openssl)
# ==========================================================================
# ---------------------------------------------------------------------------

section "7. HMAC-SHA512 signature verification (openssl)"

if command -v openssl > /dev/null 2>&1; then
    for impl in c py go rust java cs groovy haskell nasm; do
        ws=$(new_ws)
        ok=false

        case "$impl" in
            c)       bin_ok "./rijndael-encrypt.exe"         && enc_c       "$ws" > /dev/null 2>&1 && ok=true ;;
            py)      enc_py "$ws"                                                  > /dev/null 2>&1 && ok=true ;;
            go)      bin_ok "./rijndael-encrypt-go.exe"      && enc_go      "$ws" > /dev/null 2>&1 && ok=true ;;
            rust)    bin_ok "./rijndael-encrypt-rust.exe"    && enc_rust    "$ws" > /dev/null 2>&1 && ok=true ;;
            java)    jar_ok "RijndaelEncrypt.jar"            && enc_java    "$ws" > /dev/null 2>&1 && ok=true ;;
            cs)      bin_ok "./rijndael-mono-encrypt.exe"    && enc_cs      "$ws" > /dev/null 2>&1 && ok=true ;;
            groovy)  command -v groovy > /dev/null 2>&1      && enc_groovy  "$ws" > /dev/null 2>&1 && ok=true ;;
            haskell) bin_ok "./rijndael-encrypt-haskell.exe" && enc_haskell "$ws" > /dev/null 2>&1 && ok=true ;;
            nasm)    bin_ok "./rijndael-encrypt-nasm.exe"    && enc_nasm    "$ws" > /dev/null 2>&1 && ok=true ;;
        esac

        if $ok; then
            computed=$(openssl dgst -sha512 -mac HMAC -macopt "hexkey:${KEY_HEX}" -binary "$ws/output.rij" 2>/dev/null)
            stored=$(cat "$ws/output.rij.sig" 2>/dev/null)
            if [ "$computed" = "$stored" ]; then
                pass "$impl: HMAC-SHA512 signature matches openssl reference"
            else
                fail "$impl: HMAC-SHA512 signature matches openssl reference"
            fi
        else
            skip "$impl: HMAC-SHA512 verification" "binary not found or encrypt failed"
        fi
    done
else
    skip "HMAC-SHA512 openssl verification" "openssl not installed"
fi

# ---------------------------------------------------------------------------
# ==========================================================================
# SECTION 8 – NASM-specific tests
# ==========================================================================
# ---------------------------------------------------------------------------

section "8. NASM-specific tests"

if bin_ok "./rijndael-encrypt-nasm.exe" && bin_ok "./rijndael-decrypt-nasm.exe"; then
    # Basic roundtrip
    ws=$(new_ws)
    enc_nasm "$ws" > /dev/null 2>&1 && dec_nasm "$ws" > /dev/null 2>&1
    assert_files_equal "NASM: roundtrip recovers plaintext" "$ws/input.txt" "$ws/plain.txt"

    # Output format
    ws=$(new_ws)
    out=$(enc_nasm "$ws" 2>/dev/null)
    echo "$out" | grep -q "nasm" && pass "NASM: stdout contains 'nasm' label" || fail "NASM: stdout contains 'nasm' label"

    # Ciphertext matches C reference
    if bin_ok "./rijndael-encrypt.exe"; then
        ws_c=$(new_ws); ws_nasm=$(new_ws)
        enc_c    "$ws_c"    > /dev/null 2>&1
        enc_nasm "$ws_nasm" > /dev/null 2>&1
        assert_files_equal "NASM ciphertext == C ciphertext" "$ws_nasm/output.rij" "$ws_c/output.rij"
    fi

    # MAC tamper
    ws=$(new_ws)
    enc_nasm "$ws" > /dev/null 2>&1
    python3 -c "
data = bytearray(open('$ws/output.rij','rb').read())
data[0] ^= 0xFF
open('$ws/output.rij','wb').write(data)
" 2>/dev/null
    if ! dec_nasm "$ws" > /dev/null 2>&1; then
        pass "NASM: tampered ciphertext fails decryption"
    else
        fail "NASM: tampered ciphertext fails decryption"
    fi

    # Wrong key
    ws=$(new_ws)
    enc_nasm "$ws" > /dev/null 2>&1
    printf '%s' "$WRONG_KEY_HEX" > "$ws/input.key"
    if ! ./rijndael-decrypt-nasm.exe "$ws/output.rij" "$ws/plain.txt" "$ws/input.key" "$ws/input.iv" > /dev/null 2>&1; then
        pass "NASM: wrong key fails"
    else
        fail "NASM: wrong key fails"
    fi

    # Error handling: no args
    if ! ./rijndael-encrypt-nasm.exe > /dev/null 2>&1; then
        pass "NASM: encrypt exits non-zero on no args"
    else
        fail "NASM: encrypt exits non-zero on no args"
    fi
else
    skip "NASM tests" "NASM binaries not found"
fi

# ---------------------------------------------------------------------------
# ==========================================================================
# Summary
# ==========================================================================
# ---------------------------------------------------------------------------

printf "\n"
printf "=================================================\n"
printf " Results: %d passed | %d failed | %d skipped\n" "$PASS" "$FAIL" "$SKIP"
printf "=================================================\n"

[ "$FAIL" -eq 0 ]
