/**
 * Integration tests for the Groovy Rijndael encrypt/decrypt scripts.
 *
 * Run from the project root:
 *   groovy rijndael-groovy/RijndaelTest.groovy
 *
 * Uses GroovyTestCase (part of Groovy standard library — no extra deps).
 */

import groovy.test.GroovyTestCase
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class RijndaelSpec extends GroovyTestCase {

    static final String KEY_HEX       = "594193e330c8e8312f244c9cff045b73e66c301c30eb3bf0ec943a25e7a45650"
    static final String IV_HEX        = "2cef85f5259ae311034de17fda3b8369"
    static final String WRONG_KEY_HEX = "0000000000000000000000000000000000000000000000000000000000000000"
    static final String WRONG_IV_HEX  = "ffffffffffffffffffffffffffffffff"
    static final byte[] PLAINTEXT     = "my message to you, let's win".bytes

    // Walk up from CWD until we find the Makefile (project root marker)
    static final String PROJECT_ROOT = {
        def dir = new File('.').canonicalFile
        while (dir != null && !new File(dir, 'Makefile').exists()) dir = dir.parentFile
        dir?.absolutePath ?: new File('.').canonicalPath
    }()
    static final String ENC_SCRIPT = "$PROJECT_ROOT/rijndael-groovy/rijndael-encrypt.groovy"
    static final String DEC_SCRIPT = "$PROJECT_ROOT/rijndael-groovy/rijndael-decrypt.groovy"

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private File makeTempDir() {
        File dir = File.createTempDir("rijndael-groovy-test-", "")
        dir.deleteOnExit()
        dir
    }

    private void deleteDirRecursive(File dir) {
        dir.eachFile { it.delete() }
        dir.delete()
    }

    private void setupKeys(File dir, String keyHex = KEY_HEX, String ivHex = IV_HEX) {
        new File(dir, "input.key").text = keyHex
        new File(dir, "input.iv").text  = ivHex
    }

    private ProcessResult runScript(String script, String... args) {
        def cmd = ["groovy", script] + args.toList()
        def proc = new ProcessBuilder(cmd)
                .redirectErrorStream(false)
                .start()
        String stdout = proc.inputStream.text
        String stderr = proc.errorStream.text
        int rc = proc.waitFor()
        new ProcessResult(exitCode: rc, stdout: stdout, stderr: stderr)
    }

    private ProcessResult doEncrypt(File dir, byte[] pt = PLAINTEXT,
                                    String keyHex = null, String ivHex = null) {
        def keyFile = new File(dir, "input.key")
        def ivFile  = new File(dir, "input.iv")
        keyFile.text = keyHex ?: KEY_HEX
        ivFile.text  = ivHex  ?: IV_HEX
        def inputFile  = new File(dir, "input.txt")
        def outputFile = new File(dir, "output.rij")
        inputFile.bytes = pt
        runScript(ENC_SCRIPT,
                inputFile.absolutePath, outputFile.absolutePath,
                keyFile.absolutePath, ivFile.absolutePath)
    }

    private ProcessResult doDecrypt(File dir, String keyHex = null, String ivHex = null) {
        def ctFile  = new File(dir, "output.rij")
        def outFile = new File(dir, "decrypted.txt")
        def keyFile = new File(dir, "dec.key")
        def ivFile  = new File(dir, "dec.iv")
        keyFile.text = keyHex ?: KEY_HEX
        ivFile.text  = ivHex  ?: IV_HEX
        runScript(DEC_SCRIPT,
                ctFile.absolutePath, outFile.absolutePath,
                keyFile.absolutePath, ivFile.absolutePath)
    }

    private byte[] computeHmacSha512(byte[] key, byte[] data) {
        Mac mac = Mac.getInstance("HmacSHA512")
        mac.init(new SecretKeySpec(key, "HmacSHA512"))
        mac.doFinal(data)
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length()
        byte[] data = new byte[len.intdiv(2)]
        for (int i = 0; i < len; i += 2)
            data[i.intdiv(2)] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16)
        data
    }

    // -----------------------------------------------------------------------
    // Encrypt – output structure
    // -----------------------------------------------------------------------

    void testEncryptCreatesOutputFile() {
        def dir = makeTempDir()
        try {
            def r = doEncrypt(dir)
            assertEquals("encrypt: exit 0", 0, r.exitCode)
            assertTrue("encrypt: output file created", new File(dir, "output.rij").exists())
        } finally { deleteDirRecursive(dir) }
    }

    void testEncryptCreatesSigFile() {
        def dir = makeTempDir()
        try {
            doEncrypt(dir)
            assertTrue("encrypt: .sig file created", new File(dir, "output.rij.sig").exists())
        } finally { deleteDirRecursive(dir) }
    }

    void testEncryptOutputMultipleOfBlockSize() {
        def dir = makeTempDir()
        try {
            doEncrypt(dir)
            long sz = new File(dir, "output.rij").length()
            assertEquals("encrypt: ciphertext multiple of 16", 0L, sz % 16)
        } finally { deleteDirRecursive(dir) }
    }

    void testEncryptSigIs64Bytes() {
        def dir = makeTempDir()
        try {
            doEncrypt(dir)
            long sz = new File(dir, "output.rij.sig").length()
            assertEquals("encrypt: sig is 64 bytes", 64L, sz)
        } finally { deleteDirRecursive(dir) }
    }

    void testEncryptSigMatchesHmacSha512() {
        def dir = makeTempDir()
        try {
            doEncrypt(dir)
            byte[] key      = hexToBytes(KEY_HEX)
            byte[] ct       = new File(dir, "output.rij").bytes
            byte[] expected = computeHmacSha512(key, ct)
            byte[] actual   = new File(dir, "output.rij.sig").bytes
            assertTrue("encrypt: sig matches HMAC-SHA512", expected == actual)
        } finally { deleteDirRecursive(dir) }
    }

    // -----------------------------------------------------------------------
    // Encrypt – PKCS7 padding
    // -----------------------------------------------------------------------

    void testEncryptPaddingLengths() {
        def cases = [
            [0, 16], [1, 16], [15, 16],
            [16, 32], [17, 32], [28, 32], [31, 32],
            [32, 48]
        ]
        cases.each { tc ->
            int inputLen = tc[0]; int expectedLen = tc[1]
            def dir = makeTempDir()
            try {
                doEncrypt(dir, new byte[inputLen])
                long sz = new File(dir, "output.rij").length()
                assertEquals("encrypt: input ${inputLen} -> output ${expectedLen}", expectedLen, sz)
            } finally { deleteDirRecursive(dir) }
        }
    }

    // -----------------------------------------------------------------------
    // Encrypt – determinism and sensitivity
    // -----------------------------------------------------------------------

    void testEncryptDeterministic() {
        def dir1 = makeTempDir(); def dir2 = makeTempDir()
        try {
            doEncrypt(dir1); doEncrypt(dir2)
            byte[] ct1 = new File(dir1, "output.rij").bytes
            byte[] ct2 = new File(dir2, "output.rij").bytes
            assertTrue("encrypt: deterministic", ct1 == ct2)
        } finally { deleteDirRecursive(dir1); deleteDirRecursive(dir2) }
    }

    void testEncryptDifferentIvDifferentCiphertext() {
        def dir1 = makeTempDir(); def dir2 = makeTempDir()
        try {
            doEncrypt(dir1)
            doEncrypt(dir2, PLAINTEXT, null, WRONG_IV_HEX)
            byte[] ct1 = new File(dir1, "output.rij").bytes
            byte[] ct2 = new File(dir2, "output.rij").bytes
            assertFalse("encrypt: different IV -> different ciphertext", ct1 == ct2)
        } finally { deleteDirRecursive(dir1); deleteDirRecursive(dir2) }
    }

    void testEncryptDifferentKeyDifferentCiphertext() {
        def dir1 = makeTempDir(); def dir2 = makeTempDir()
        try {
            doEncrypt(dir1)
            doEncrypt(dir2, PLAINTEXT, WRONG_KEY_HEX, null)
            byte[] ct1 = new File(dir1, "output.rij").bytes
            byte[] ct2 = new File(dir2, "output.rij").bytes
            assertFalse("encrypt: different key -> different ciphertext", ct1 == ct2)
        } finally { deleteDirRecursive(dir1); deleteDirRecursive(dir2) }
    }

    // -----------------------------------------------------------------------
    // Encrypt – stdout messages
    // -----------------------------------------------------------------------

    void testEncryptStdoutLabel() {
        def dir = makeTempDir()
        try {
            def r = doEncrypt(dir)
            assertTrue("encrypt: stdout contains Groovy label",
                    r.stdout.contains("[ Groovy | encrypt ]"))
        } finally { deleteDirRecursive(dir) }
    }

    void testEncryptStdoutAlgorithmName() {
        def dir = makeTempDir()
        try {
            def r = doEncrypt(dir)
            assertTrue("encrypt: stdout contains algorithm name",
                    r.stdout.contains("AES-256/CBC/PKCS7"))
        } finally { deleteDirRecursive(dir) }
    }

    // -----------------------------------------------------------------------
    // Encrypt – error handling
    // -----------------------------------------------------------------------

    void testEncryptExitOneNoArgs() {
        def r = runScript(ENC_SCRIPT)
        assertTrue("encrypt: non-zero exit on no args", r.exitCode != 0)
    }

    void testEncryptNonzeroMissingInput() {
        def dir = makeTempDir()
        try {
            new File(dir, "input.key").text = KEY_HEX
            new File(dir, "input.iv").text  = IV_HEX
            def r = runScript(ENC_SCRIPT,
                    new File(dir, "nonexistent.txt").absolutePath,
                    new File(dir, "output.rij").absolutePath,
                    new File(dir, "input.key").absolutePath,
                    new File(dir, "input.iv").absolutePath)
            assertTrue("encrypt: non-zero exit on missing input", r.exitCode != 0)
        } finally { deleteDirRecursive(dir) }
    }

    // -----------------------------------------------------------------------
    // Decrypt – roundtrip
    // -----------------------------------------------------------------------

    void testDecryptRoundtrip() {
        def dir = makeTempDir()
        try {
            def er = doEncrypt(dir)
            assertEquals("roundtrip: encrypt exits 0", 0, er.exitCode)
            def dr = doDecrypt(dir)
            assertEquals("roundtrip: decrypt exits 0", 0, dr.exitCode)
            byte[] got = new File(dir, "decrypted.txt").bytes
            assertTrue("roundtrip: plaintext recovered", got == PLAINTEXT)
        } finally { deleteDirRecursive(dir) }
    }

    void testDecryptRoundtripEmptyInput() {
        def dir = makeTempDir()
        try {
            doEncrypt(dir, new byte[0])
            def dr = doDecrypt(dir)
            assertEquals("roundtrip empty: decrypt exits 0", 0, dr.exitCode)
            long sz = new File(dir, "decrypted.txt").length()
            assertEquals("roundtrip empty: output is 0 bytes", 0L, sz)
        } finally { deleteDirRecursive(dir) }
    }

    void testDecryptRoundtripExactBlock() {
        def dir = makeTempDir()
        byte[] pt = "1234567890abcdef".bytes
        try {
            doEncrypt(dir, pt)
            def dr = doDecrypt(dir)
            assertEquals("roundtrip 16-byte: decrypt exits 0", 0, dr.exitCode)
            byte[] got = new File(dir, "decrypted.txt").bytes
            assertTrue("roundtrip 16-byte: plaintext recovered", got == pt)
        } finally { deleteDirRecursive(dir) }
    }

    void testDecryptRoundtripLargeInput() {
        def dir = makeTempDir()
        byte[] pt = (0..<8192).collect { (byte)(it & 0xFF) } as byte[]
        try {
            doEncrypt(dir, pt)
            def dr = doDecrypt(dir)
            assertEquals("roundtrip large: decrypt exits 0", 0, dr.exitCode)
            byte[] got = new File(dir, "decrypted.txt").bytes
            assertTrue("roundtrip large: plaintext recovered", got == pt)
        } finally { deleteDirRecursive(dir) }
    }

    // -----------------------------------------------------------------------
    // Decrypt – MAC verification
    // -----------------------------------------------------------------------

    void testDecryptMacVerifiedInStdout() {
        def dir = makeTempDir()
        try {
            doEncrypt(dir)
            def dr = doDecrypt(dir)
            assertEquals("decrypt: exits 0", 0, dr.exitCode)
            assertTrue("decrypt: MAC verified OK in stdout",
                    dr.stdout.contains("verified OK") || dr.stdout.contains("WARNING"))
        } finally { deleteDirRecursive(dir) }
    }

    void testDecryptTamperedCiphertextFails() {
        def dir = makeTempDir()
        try {
            doEncrypt(dir)
            def ctFile = new File(dir, "output.rij")
            byte[] ct = ctFile.bytes
            ct[0] = (byte)(ct[0] ^ 0xFF)
            ctFile.bytes = ct
            def dr = doDecrypt(dir)
            assertTrue("decrypt: tampered ciphertext fails", dr.exitCode != 0)
        } finally { deleteDirRecursive(dir) }
    }

    void testDecryptTamperedSigFails() {
        def dir = makeTempDir()
        try {
            doEncrypt(dir)
            def sigFile = new File(dir, "output.rij.sig")
            byte[] sig = sigFile.bytes
            sig[0] = (byte)(sig[0] ^ 0xFF)
            sigFile.bytes = sig
            def dr = doDecrypt(dir)
            assertTrue("decrypt: tampered sig fails", dr.exitCode != 0)
        } finally { deleteDirRecursive(dir) }
    }

    void testDecryptWrongKeyFails() {
        def dir = makeTempDir()
        try {
            doEncrypt(dir)
            def dr = doDecrypt(dir, WRONG_KEY_HEX, null)
            assertTrue("decrypt: wrong key fails", dr.exitCode != 0)
        } finally { deleteDirRecursive(dir) }
    }

    // -----------------------------------------------------------------------
    // Decrypt – stdout messages
    // -----------------------------------------------------------------------

    void testDecryptStdoutLabel() {
        def dir = makeTempDir()
        try {
            doEncrypt(dir)
            def dr = doDecrypt(dir)
            assertTrue("decrypt: stdout contains Groovy label",
                    dr.stdout.contains("[ Groovy | decrypt ]"))
        } finally { deleteDirRecursive(dir) }
    }

    // -----------------------------------------------------------------------
    // Decrypt – error handling
    // -----------------------------------------------------------------------

    void testDecryptNonzeroMissingCiphertext() {
        def dir = makeTempDir()
        try {
            new File(dir, "dec.key").text = KEY_HEX
            new File(dir, "dec.iv").text  = IV_HEX
            def r = runScript(DEC_SCRIPT,
                    new File(dir, "nonexistent.rij").absolutePath,
                    new File(dir, "out.txt").absolutePath,
                    new File(dir, "dec.key").absolutePath,
                    new File(dir, "dec.iv").absolutePath)
            assertTrue("decrypt: non-zero exit on missing ciphertext", r.exitCode != 0)
        } finally { deleteDirRecursive(dir) }
    }
}

// -----------------------------------------------------------------------
// Value object for process results
// -----------------------------------------------------------------------

class ProcessResult {
    int    exitCode
    String stdout
    String stderr
}

// -----------------------------------------------------------------------
// Entry point
// -----------------------------------------------------------------------

def suite = new junit.framework.TestSuite(RijndaelSpec)
def result = junit.textui.TestRunner.run(suite)
System.exit(result.wasSuccessful() ? 0 : 1)
