package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	keyHex       = "594193e330c8e8312f244c9cff045b73e66c301c30eb3bf0ec943a25e7a45650"
	ivHex        = "2cef85f5259ae311034de17fda3b8369"
	wrongKeyHex  = "0000000000000000000000000000000000000000000000000000000000000000"
	wrongIVHex   = "ffffffffffffffffffffffffffffffff"
)

var plaintext = []byte("my message to you, let's win") // 28 bytes
var binaryPath string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "rijndael-enc-test-*")
	if err != nil {
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	binName := "rijndael-encrypt-test"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binaryPath = filepath.Join(tmp, binName)

	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	_, srcDir, _, _ := runtime.Caller(0)
	cmd.Dir = filepath.Dir(srcDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		println("build failed:", string(out))
		os.Exit(1)
	}
	os.Exit(m.Run())
}

type workspace struct {
	dir     string
	keyFile string
	ivFile  string
}

func newWorkspace(t *testing.T) *workspace {
	t.Helper()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "input.key")
	ivFile := filepath.Join(dir, "input.iv")
	if err := os.WriteFile(keyFile, []byte(keyHex), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ivFile, []byte(ivHex), 0600); err != nil {
		t.Fatal(err)
	}
	return &workspace{dir: dir, keyFile: keyFile, ivFile: ivFile}
}

func (w *workspace) runEncrypt(t *testing.T, pt []byte, opts ...string) (result *exec.Cmd, inFile, outFile string) {
	t.Helper()
	inFile = filepath.Join(w.dir, "input.txt")
	outFile = filepath.Join(w.dir, "output.rij")
	if err := os.WriteFile(inFile, pt, 0644); err != nil {
		t.Fatal(err)
	}
	keyFile := w.keyFile
	ivFile := w.ivFile
	for i := 0; i+1 < len(opts); i += 2 {
		switch opts[i] {
		case "key":
			keyFile = filepath.Join(w.dir, "custom.key")
			os.WriteFile(keyFile, []byte(opts[i+1]), 0600)
		case "iv":
			ivFile = filepath.Join(w.dir, "custom.iv")
			os.WriteFile(ivFile, []byte(opts[i+1]), 0600)
		}
	}
	return exec.Command(binaryPath, inFile, outFile, keyFile, ivFile), inFile, outFile
}

func runAndCapture(t *testing.T, cmd *exec.Cmd) (stdout, stderr string, exitCode int) {
	t.Helper()
	out, err := cmd.Output()
	stdout = string(out)
	exitCode = 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			exitCode = exit.ExitCode()
			stderr = string(exit.Stderr)
		} else {
			t.Fatalf("exec error: %v", err)
		}
	}
	return
}

// ---------------------------------------------------------------------------
// Output structure
// ---------------------------------------------------------------------------

func TestEncryptCreatesOutputFile(t *testing.T) {
	w := newWorkspace(t)
	cmd, _, outFile := w.runEncrypt(t, plaintext)
	stdout, _, code := runAndCapture(t, cmd)
	_ = stdout
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(outFile); os.IsNotExist(err) {
		t.Fatal("output file not created")
	}
}

func TestEncryptCreatesSigFile(t *testing.T) {
	w := newWorkspace(t)
	cmd, _, outFile := w.runEncrypt(t, plaintext)
	if _, _, code := runAndCapture(t, cmd); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(outFile + ".sig"); os.IsNotExist(err) {
		t.Fatal(".sig file not created")
	}
}

func TestEncryptOutputMultipleOfBlockSize(t *testing.T) {
	w := newWorkspace(t)
	cmd, _, outFile := w.runEncrypt(t, plaintext)
	if _, _, code := runAndCapture(t, cmd); code != 0 {
		t.Fatalf("exit %d", code)
	}
	data, _ := os.ReadFile(outFile)
	if len(data)%16 != 0 {
		t.Fatalf("ciphertext length %d not multiple of 16", len(data))
	}
}

func TestEncryptSigIs64Bytes(t *testing.T) {
	w := newWorkspace(t)
	cmd, _, outFile := w.runEncrypt(t, plaintext)
	if _, _, code := runAndCapture(t, cmd); code != 0 {
		t.Fatalf("exit %d", code)
	}
	sig, _ := os.ReadFile(outFile + ".sig")
	if len(sig) != 64 {
		t.Fatalf("sig length %d, want 64", len(sig))
	}
}

// ---------------------------------------------------------------------------
// PKCS7 padding
// ---------------------------------------------------------------------------

func TestEncryptPaddingLengths(t *testing.T) {
	cases := []struct {
		inputLen  int
		outputLen int
	}{
		{0, 16},
		{1, 16},
		{15, 16},
		{16, 32},
		{17, 32},
		{28, 32},
		{31, 32},
		{32, 48},
	}
	for _, tc := range cases {
		t.Run("", func(t *testing.T) {
			w := newWorkspace(t)
			cmd, _, outFile := w.runEncrypt(t, make([]byte, tc.inputLen))
			if _, _, code := runAndCapture(t, cmd); code != 0 {
				t.Fatalf("exit %d for input len %d", code, tc.inputLen)
			}
			data, _ := os.ReadFile(outFile)
			if len(data) != tc.outputLen {
				t.Fatalf("input %d: got output len %d, want %d",
					tc.inputLen, len(data), tc.outputLen)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HMAC-SHA512 signature
// ---------------------------------------------------------------------------

func TestEncryptSigIsValidHMACSHA512(t *testing.T) {
	w := newWorkspace(t)
	cmd, _, outFile := w.runEncrypt(t, plaintext)
	if _, _, code := runAndCapture(t, cmd); code != 0 {
		t.Fatalf("exit %d", code)
	}
	key, _ := hex.DecodeString(keyHex)
	ct, _ := os.ReadFile(outFile)
	mac := hmac.New(sha512.New, key)
	mac.Write(ct)
	expected := mac.Sum(nil)
	got, _ := os.ReadFile(outFile + ".sig")
	if string(got) != string(expected) {
		t.Fatal("sig does not match HMAC-SHA512 of ciphertext")
	}
}

// ---------------------------------------------------------------------------
// Determinism and key/IV sensitivity
// ---------------------------------------------------------------------------

func TestEncryptDeterministicSameKeyIV(t *testing.T) {
	w1 := newWorkspace(t)
	cmd1, _, out1 := w1.runEncrypt(t, plaintext)
	runAndCapture(t, cmd1)
	ct1, _ := os.ReadFile(out1)

	w2 := newWorkspace(t)
	cmd2, _, out2 := w2.runEncrypt(t, plaintext)
	runAndCapture(t, cmd2)
	ct2, _ := os.ReadFile(out2)

	if string(ct1) != string(ct2) {
		t.Fatal("same key/IV/plaintext produced different ciphertexts")
	}
}

func TestEncryptDifferentIVDifferentCiphertext(t *testing.T) {
	w1 := newWorkspace(t)
	cmd1, _, out1 := w1.runEncrypt(t, plaintext)
	runAndCapture(t, cmd1)
	ct1, _ := os.ReadFile(out1)

	w2 := newWorkspace(t)
	cmd2, _, out2 := w2.runEncrypt(t, plaintext, "iv", wrongIVHex)
	runAndCapture(t, cmd2)
	ct2, _ := os.ReadFile(out2)

	if string(ct1) == string(ct2) {
		t.Fatal("different IV produced same ciphertext")
	}
}

func TestEncryptDifferentKeyDifferentCiphertext(t *testing.T) {
	w1 := newWorkspace(t)
	cmd1, _, out1 := w1.runEncrypt(t, plaintext)
	runAndCapture(t, cmd1)
	ct1, _ := os.ReadFile(out1)

	w2 := newWorkspace(t)
	cmd2, _, out2 := w2.runEncrypt(t, plaintext, "key", wrongKeyHex)
	runAndCapture(t, cmd2)
	ct2, _ := os.ReadFile(out2)

	if string(ct1) == string(ct2) {
		t.Fatal("different key produced same ciphertext")
	}
}

// ---------------------------------------------------------------------------
// Stdout messages
// ---------------------------------------------------------------------------

func TestEncryptStdoutContainsLanguageLabel(t *testing.T) {
	w := newWorkspace(t)
	cmd, _, _ := w.runEncrypt(t, plaintext)
	stdout, _, code := runAndCapture(t, cmd)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, "[ Go | encrypt ]") {
		t.Fatalf("stdout missing language label: %q", stdout)
	}
}

func TestEncryptStdoutContainsAlgorithmName(t *testing.T) {
	w := newWorkspace(t)
	cmd, _, _ := w.runEncrypt(t, plaintext)
	stdout, _, _ := runAndCapture(t, cmd)
	if !strings.Contains(stdout, "AES-256/CBC/PKCS7") {
		t.Fatalf("stdout missing algorithm name: %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

func TestEncryptExitOneOnTooFewArgs(t *testing.T) {
	cmd := exec.Command(binaryPath, "only_one")
	_, _, code := runAndCapture(t, cmd)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
}

func TestEncryptExitOneOnNoArgs(t *testing.T) {
	cmd := exec.Command(binaryPath)
	_, _, code := runAndCapture(t, cmd)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
}

func TestEncryptNonzeroOnMissingInputFile(t *testing.T) {
	w := newWorkspace(t)
	cmd := exec.Command(binaryPath,
		filepath.Join(w.dir, "nonexistent.txt"),
		filepath.Join(w.dir, "output.rij"),
		w.keyFile, w.ivFile)
	_, _, code := runAndCapture(t, cmd)
	if code == 0 {
		t.Fatal("expected non-zero exit for missing input file")
	}
}

func TestEncryptNonzeroOnInvalidKeyLength(t *testing.T) {
	w := newWorkspace(t)
	shortKey := filepath.Join(w.dir, "short.key")
	os.WriteFile(shortKey, []byte("deadbeef"), 0600)
	inFile := filepath.Join(w.dir, "input.txt")
	os.WriteFile(inFile, plaintext, 0644)
	cmd := exec.Command(binaryPath, inFile,
		filepath.Join(w.dir, "output.rij"),
		shortKey, w.ivFile)
	_, _, code := runAndCapture(t, cmd)
	if code == 0 {
		t.Fatal("expected non-zero exit for invalid key length")
	}
}
