#!/bin/sh

openssl rand -hex 16 > input.iv

if [ ! -f input.key ]; then
    openssl rand -hex 32 > input.key
fi

if [ ! -f input.txt ]; then
    printf "Enter message: "
    read -r message
    printf "%s" "$message" > input.txt
fi

rm plain*.txt

./rijndael-encrypt.exe input.txt output.txt.rij input.key input.iv
./rijndael-python/rijndael-encrypt.py input.txt output-python.txt.rij input.key input.iv
./rijndael-mono-encrypt.exe input.txt output-mono.txt.rij input.key input.iv
java -jar RijndaelEncrypt.jar input.txt output.java.txt.rij input.key input.iv
./rijndael-encrypt-rust.exe input.txt output-rust.txt.rij input.key input.iv
./rijndael-encrypt-go.exe input.txt output-go.txt.rij input.key input.iv
./rijndael-encrypt-haskell.exe input.txt output-haskell.txt.rij input.key input.iv
groovy rijndael-groovy/rijndael-encrypt.groovy input.txt output-groovy.txt.rij input.key input.iv
./rijndael-encrypt-nasm.exe input.txt output-nasm.txt.rij input.key input.iv

./rijndael-decrypt.exe output.txt.rij plain-c.txt input.key input.iv
./rijndael-mono-decrypt.exe output-mono.txt.rij plain-mono.txt input.key input.iv
java -jar RijndaelDecrypt.jar output.java.txt.rij plain-java.txt input.key input.iv
./rijndael-python/rijndael-decrypt.py output-python.txt.rij plain-python.txt input.key input.iv
./rijndael-decrypt-rust.exe output-rust.txt.rij plain-rust.txt input.key input.iv
./rijndael-decrypt-go.exe output-go.txt.rij plain-go.txt input.key input.iv
./rijndael-decrypt-haskell.exe output-haskell.txt.rij plain-haskell.txt input.key input.iv
groovy rijndael-groovy/rijndael-decrypt.groovy output-groovy.txt.rij plain-groovy.txt input.key input.iv
./rijndael-decrypt-nasm.exe output-nasm.txt.rij plain-nasm.txt input.key input.iv

verify() {
    label="$1"
    file="$2"
    ref="$3"
    if [ "$(sha256sum "$file" | cut -d' ' -f1)" = "$ref" ]; then
        printf "  %-8s : PASS\n" "$label"
    else
        printf "  %-8s : FAIL\n" "$label"
    fi
}

plain_ref=$(sha256sum input.txt | cut -d' ' -f1)
printf "\n--- plaintext verification (ref: input.txt) ---\n"
printf "  hash     : %s\n" "$plain_ref"
verify "c"      plain-c.txt      "$plain_ref"
verify "go"     plain-go.txt     "$plain_ref"
verify "java"   plain-java.txt   "$plain_ref"
verify "mono"   plain-mono.txt   "$plain_ref"
verify "python" plain-python.txt "$plain_ref"
verify "rust"   plain-rust.txt      "$plain_ref"
verify "haskell" plain-haskell.txt  "$plain_ref"
verify "groovy"  plain-groovy.txt   "$plain_ref"
verify "nasm"    plain-nasm.txt     "$plain_ref"

rij_ref=$(sha256sum output.txt.rij | cut -d' ' -f1)
printf "\n--- ciphertext verification (ref: output.txt.rij) ---\n"
printf "  hash     : %s\n" "$rij_ref"
verify "c"      output.txt.rij        "$rij_ref"
verify "go"     output-go.txt.rij     "$rij_ref"
verify "java"   output.java.txt.rij   "$rij_ref"
verify "mono"   output-mono.txt.rij   "$rij_ref"
verify "python" output-python.txt.rij "$rij_ref"
verify "rust"    output-rust.txt.rij    "$rij_ref"
verify "haskell" output-haskell.txt.rij "$rij_ref"
verify "groovy"  output-groovy.txt.rij  "$rij_ref"
verify "nasm"    output-nasm.txt.rij    "$rij_ref"

key_hex=$(cat input.key)

verify_sig() {
    label="$1"
    file="$2"
    if openssl dgst -sha512 -mac HMAC -macopt "hexkey:${key_hex}" -binary "$file" 2>/dev/null \
       | cmp -s - "${file}.sig"; then
        printf "  %-8s : PASS\n" "$label"
    else
        printf "  %-8s : FAIL\n" "$label"
    fi
}

printf "\n--- HMAC-SHA512 verification (openssl) ---\n"
verify_sig "c"       output.txt.rij
verify_sig "go"      output-go.txt.rij
verify_sig "java"    output.java.txt.rij
verify_sig "python"  output-python.txt.rij
verify_sig "rust"    output-rust.txt.rij
verify_sig "haskell" output-haskell.txt.rij
verify_sig "mono"    output-mono.txt.rij
verify_sig "groovy"  output-groovy.txt.rij
verify_sig "nasm"    output-nasm.txt.rij

exit 0
