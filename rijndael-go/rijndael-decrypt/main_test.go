package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	keyHex      = "594193e330c8e8312f244c9cff045b73e66c301c30eb3bf0ec943a25e7a45650"
	ivHex       = "2cef85f5259ae311034de17fda3b8369"
	wrongKeyHex = "0000000000000000000000000000000000000000000000000000000000000000"
	wrongIVHex  = "ffffffffffffffffffffffffffffffff"
)

var plaintext = []byte("my message to you, let's win")

var (
	encBin string
	decBin string
)

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "rijndael-dec-test-*")
	if err != nil {
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	encBin = filepath.Join(tmp, "rijndael-encrypt"+suffix)
	decBin = filepath.Join(tmp, "rijndael-decrypt"+suffix)

	_, srcFile, _, _ := runtime.Caller(0)
	srcDir := filepath.Dir(srcFile)
	encSrcDir := filepath.Join(srcDir, "..", "rijndael-encrypt")

	if out, err := exec.Command("go", "build", "-o", encBin, encSrcDir).CombinedOutput(); err != nil {
		println("build encrypt failed:", string(out))
		os.Exit(1)
	}
	if out, err := exec.Command("go", "build", "-o", decBin, ".").CombinedOutput(); err != nil {
		println("build decrypt failed:", string(out))
		os.Exit(1)
	}
	os.Exit(m.Run())
}

type ws struct{ dir, keyFile, ivFile string }

func newWS(t *testing.T) *ws {
	t.Helper()
	dir := t.TempDir()
	kf := filepath.Join(dir, "input.key")
	ivf := filepath.Join(dir, "input.iv")
	os.WriteFile(kf, []byte(keyHex), 0600)
	os.WriteFile(ivf, []byte(ivHex), 0600)
	return &ws{dir, kf, ivf}
}

func (w *ws) encrypt(t *testing.T, pt []byte, keyOverride, ivOverride string) string {
	t.Helper()
	kf, ivf := w.keyFile, w.ivFile
	if keyOverride != "" {
		kf = filepath.Join(w.dir, "enc.key")
		os.WriteFile(kf, []byte(keyOverride), 0600)
	}
	if ivOverride != "" {
		ivf = filepath.Join(w.dir, "enc.iv")
		os.WriteFile(ivf, []byte(ivOverride), 0600)
	}
	inFile := filepath.Join(w.dir, "input.txt")
	outFile := filepath.Join(w.dir, "output.rij")
	os.WriteFile(inFile, pt, 0644)
	out, err := exec.Command(encBin, inFile, outFile, kf, ivf).CombinedOutput()
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}
	return outFile
}

func (w *ws) runDecrypt(t *testing.T, ctFile, keyOverride, ivOverride string) (string, int) {
	t.Helper()
	kf, ivf := w.keyFile, w.ivFile
	if keyOverride != "" {
		kf = filepath.Join(w.dir, "dec.key")
		os.WriteFile(kf, []byte(keyOverride), 0600)
	}
	if ivOverride != "" {
		ivf = filepath.Join(w.dir, "dec.iv")
		os.WriteFile(ivf, []byte(ivOverride), 0600)
	}
	outFile := filepath.Join(w.dir, "decrypted.txt")
	cmd := exec.Command(decBin, ctFile, outFile, kf, ivf)
	out, err := cmd.Output()
	_ = out
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return string(exit.Stderr), exit.ExitCode()
		}
		t.Fatalf("exec error: %v", err)
	}
	return "", 0
}

func capture(t *testing.T, cmd *exec.Cmd) (stdout, stderr string, code int) {
	t.Helper()
	out, err := cmd.Output()
	stdout = string(out)
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return stdout, string(exit.Stderr), exit.ExitCode()
		}
		t.Fatalf("exec error: %v", err)
	}
	return stdout, "", 0
}

// ---------------------------------------------------------------------------
// Roundtrip
// ---------------------------------------------------------------------------

func TestDecryptRoundtrip(t *testing.T) {
	w := newWS(t)
	ctFile := w.encrypt(t, plaintext, "", "")
	_, code := w.runDecrypt(t, ctFile, "", "")
	if code != 0 {
		t.Fatalf("decrypt exit %d", code)
	}
	got, _ := os.ReadFile(filepath.Join(w.dir, "decrypted.txt"))
	if string(got) != string(plaintext) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestDecryptRoundtripEmptyInput(t *testing.T) {
	w := newWS(t)
	ctFile := w.encrypt(t, []byte{}, "", "")
	_, code := w.runDecrypt(t, ctFile, "", "")
	if code != 0 {
		t.Fatalf("decrypt exit %d", code)
	}
	got, _ := os.ReadFile(filepath.Join(w.dir, "decrypted.txt"))
	if len(got) != 0 {
		t.Fatalf("expected empty output, got %d bytes", len(got))
	}
}

func TestDecryptRoundtripExactBlock(t *testing.T) {
	pt := []byte("1234567890abcdef")
	w := newWS(t)
	ctFile := w.encrypt(t, pt, "", "")
	_, code := w.runDecrypt(t, ctFile, "", "")
	if code != 0 {
		t.Fatalf("decrypt exit %d", code)
	}
	got, _ := os.ReadFile(filepath.Join(w.dir, "decrypted.txt"))
	if string(got) != string(pt) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", got, pt)
	}
}

func TestDecryptRoundtripLargeInput(t *testing.T) {
	pt := append(make([]byte, 4096), make([]byte, 4095)...)
	for i := range pt[:4096] {
		pt[i] = 0xAA
	}
	for i := range pt[4096:] {
		pt[4096+i] = 0xBB
	}
	w := newWS(t)
	ctFile := w.encrypt(t, pt, "", "")
	_, code := w.runDecrypt(t, ctFile, "", "")
	if code != 0 {
		t.Fatalf("decrypt exit %d", code)
	}
	got, _ := os.ReadFile(filepath.Join(w.dir, "decrypted.txt"))
	if string(got) != string(pt) {
		t.Fatal("roundtrip mismatch on large input")
	}
}

func TestDecryptRoundtripAllByteValues(t *testing.T) {
	pt := make([]byte, 256)
	for i := range pt {
		pt[i] = byte(i)
	}
	w := newWS(t)
	ctFile := w.encrypt(t, pt, "", "")
	_, code := w.runDecrypt(t, ctFile, "", "")
	if code != 0 {
		t.Fatalf("decrypt exit %d", code)
	}
	got, _ := os.ReadFile(filepath.Join(w.dir, "decrypted.txt"))
	if string(got) != string(pt) {
		t.Fatal("roundtrip mismatch for all-byte-values input")
	}
}

// ---------------------------------------------------------------------------
// MAC verification
// ---------------------------------------------------------------------------

func TestDecryptMACVerifiedInStdout(t *testing.T) {
	w := newWS(t)
	ctFile := w.encrypt(t, plaintext, "", "")
	outFile := filepath.Join(w.dir, "decrypted.txt")
	cmd := exec.Command(decBin, ctFile, outFile, w.keyFile, w.ivFile)
	stdout, _, code := capture(t, cmd)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, "verified OK") {
		t.Fatalf("stdout missing MAC verified OK: %q", stdout)
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	w := newWS(t)
	ctFile := w.encrypt(t, plaintext, "", "")
	data, _ := os.ReadFile(ctFile)
	data[0] ^= 0xFF
	os.WriteFile(ctFile, data, 0644)
	_, code := w.runDecrypt(t, ctFile, "", "")
	if code == 0 {
		t.Fatal("expected non-zero exit on tampered ciphertext")
	}
}

func TestDecryptTamperedSigFails(t *testing.T) {
	w := newWS(t)
	ctFile := w.encrypt(t, plaintext, "", "")
	sigFile := ctFile + ".sig"
	data, _ := os.ReadFile(sigFile)
	data[0] ^= 0xFF
	os.WriteFile(sigFile, data, 0600)
	_, code := w.runDecrypt(t, ctFile, "", "")
	if code == 0 {
		t.Fatal("expected non-zero exit on tampered sig")
	}
}

func TestDecryptMissingSigIssuesWarning(t *testing.T) {
	w := newWS(t)
	ctFile := w.encrypt(t, plaintext, "", "")
	os.Remove(ctFile + ".sig")
	outFile := filepath.Join(w.dir, "decrypted.txt")
	cmd := exec.Command(decBin, ctFile, outFile, w.keyFile, w.ivFile)
	stdout, _, code := capture(t, cmd)
	if code != 0 {
		t.Fatalf("Go decrypt should succeed (with warning) when .sig missing, got exit %d", code)
	}
	if !strings.Contains(stdout, "WARNING") {
		t.Fatalf("expected WARNING in stdout when .sig missing: %q", stdout)
	}
}

func TestDecryptWrongKeyFailsMAC(t *testing.T) {
	w := newWS(t)
	ctFile := w.encrypt(t, plaintext, "", "")
	_, code := w.runDecrypt(t, ctFile, wrongKeyHex, "")
	if code == 0 {
		t.Fatal("expected non-zero exit when decrypting with wrong key")
	}
}

// ---------------------------------------------------------------------------
// Stdout messages
// ---------------------------------------------------------------------------

func TestDecryptStdoutContainsLanguageLabel(t *testing.T) {
	w := newWS(t)
	ctFile := w.encrypt(t, plaintext, "", "")
	outFile := filepath.Join(w.dir, "decrypted.txt")
	cmd := exec.Command(decBin, ctFile, outFile, w.keyFile, w.ivFile)
	stdout, _, _ := capture(t, cmd)
	if !strings.Contains(stdout, "[ Go | decrypt ]") {
		t.Fatalf("stdout missing language label: %q", stdout)
	}
}

func TestDecryptStdoutContainsAlgorithmName(t *testing.T) {
	w := newWS(t)
	ctFile := w.encrypt(t, plaintext, "", "")
	outFile := filepath.Join(w.dir, "decrypted.txt")
	cmd := exec.Command(decBin, ctFile, outFile, w.keyFile, w.ivFile)
	stdout, _, _ := capture(t, cmd)
	if !strings.Contains(stdout, "AES-256/CBC/PKCS7") {
		t.Fatalf("stdout missing algorithm name: %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

func TestDecryptExitOneOnTooFewArgs(t *testing.T) {
	cmd := exec.Command(decBin, "a", "b")
	_, _, code := capture(t, cmd)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
}

func TestDecryptExitOneOnNoArgs(t *testing.T) {
	cmd := exec.Command(decBin)
	_, _, code := capture(t, cmd)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
}

func TestDecryptNonzeroOnMissingCiphertextFile(t *testing.T) {
	w := newWS(t)
	_, code := w.runDecrypt(t, filepath.Join(w.dir, "nonexistent.rij"), "", "")
	if code == 0 {
		t.Fatal("expected non-zero exit for missing ciphertext file")
	}
}

func TestDecryptNonzeroOnInvalidKeyLength(t *testing.T) {
	w := newWS(t)
	ctFile := w.encrypt(t, plaintext, "", "")
	shortKeyFile := filepath.Join(w.dir, "short.key")
	os.WriteFile(shortKeyFile, []byte("deadbeef"), 0600)
	outFile := filepath.Join(w.dir, "out.txt")
	cmd := exec.Command(decBin, ctFile, outFile, shortKeyFile, w.ivFile)
	_, _, code := capture(t, cmd)
	if code == 0 {
		t.Fatal("expected non-zero exit for invalid key")
	}
}
