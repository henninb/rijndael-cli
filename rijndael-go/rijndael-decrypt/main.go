package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintf(os.Stderr, "Usage: %s <ifname> <ofname> <keyfname> <ivfname>\n", os.Args[0])
		os.Exit(1)
	}

	ifname   := os.Args[1]
	ofname   := os.Args[2]
	keyfname := os.Args[3]
	ivfname  := os.Args[4]

	fmt.Println("[ Go | decrypt ] algorithm  : AES-256/CBC/PKCS7")

	keyHex, err := os.ReadFile(keyfname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ABORT: cannot read key file: %v\n", err)
		os.Exit(1)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	if err != nil || len(key) != 32 {
		fmt.Fprintf(os.Stderr, "ABORT: invalid key (need 64 hex chars)\n")
		os.Exit(1)
	}

	ivHex, err := os.ReadFile(ivfname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ABORT: cannot read iv file: %v\n", err)
		os.Exit(1)
	}
	iv, err := hex.DecodeString(strings.TrimSpace(string(ivHex)))
	if err != nil || len(iv) != 16 {
		fmt.Fprintf(os.Stderr, "ABORT: invalid iv (need 32 hex chars)\n")
		os.Exit(1)
	}

	ciphertext, err := os.ReadFile(ifname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ABORT: cannot read input file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[ Go | decrypt ] input      : %d bytes\n", len(ciphertext))

	if storedSig, err := os.ReadFile(ifname + ".sig"); err == nil {
		mac := hmac.New(sha512.New, key)
		mac.Write(ciphertext)
		if subtle.ConstantTimeCompare(storedSig, mac.Sum(nil)) != 1 {
			fmt.Fprintln(os.Stderr, "ABORT: MAC verification failed")
			os.Exit(1)
		}
		fmt.Println("[ Go | decrypt ] MAC        : verified OK")
	} else {
		fmt.Println("[ Go | decrypt ] WARNING    : no .sig file — skipping MAC verification")
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		fmt.Fprintf(os.Stderr, "ABORT: ciphertext length is not a multiple of block size\n")
		os.Exit(1)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ABORT: aes.NewCipher: %v\n", err)
		os.Exit(1)
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	padLen := int(plaintext[len(plaintext)-1])
	if padLen < 1 || padLen > aes.BlockSize {
		fmt.Fprintf(os.Stderr, "ABORT: invalid PKCS7 padding\n")
		os.Exit(1)
	}
	plaintext = plaintext[:len(plaintext)-padLen]

	if err := os.WriteFile(ofname, plaintext, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "ABORT: cannot write output file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[ Go | decrypt ] output     : %s\n", ofname)
}
