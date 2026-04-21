package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
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

	fmt.Println("[ Go | encrypt ] algorithm  : AES-256/CBC/PKCS7")

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

	plaintext, err := os.ReadFile(ifname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ABORT: cannot read input file: %v\n", err)
		os.Exit(1)
	}

	padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	fmt.Printf("[ Go | encrypt ] input      : %d bytes  ->  padded : %d bytes\n", len(plaintext), len(padded))

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ABORT: aes.NewCipher: %v\n", err)
		os.Exit(1)
	}

	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	if err := os.WriteFile(ofname, ciphertext, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "ABORT: cannot write output file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[ Go | encrypt ] output     : %s\n", ofname)

	mac := hmac.New(sha512.New, key)
	mac.Write(ciphertext)
	if err := os.WriteFile(ofname+".sig", mac.Sum(nil), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "ABORT: cannot write sig file: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[ Go | encrypt ] signature  : written")
}
