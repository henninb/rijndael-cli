import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;

/**
 * Integration tests for RijndaelEncrypt / RijndaelDecrypt JARs.
 *
 * Compile and run:
 *   cd rijndael-java
 *   javac RijndaelTest.java
 *   java RijndaelTest
 *
 * Requires the JARs to be already built (make linux).
 */
public class RijndaelTest {

    static final String KEY_HEX       = "594193e330c8e8312f244c9cff045b73e66c301c30eb3bf0ec943a25e7a45650";
    static final String IV_HEX        = "2cef85f5259ae311034de17fda3b8369";
    static final String WRONG_KEY_HEX = "0000000000000000000000000000000000000000000000000000000000000000";
    static final String WRONG_IV_HEX  = "ffffffffffffffffffffffffffffffff";
    static final byte[] PLAINTEXT     = "my message to you, let's win".getBytes();

    // Resolved relative to the working directory (project root) when run as:
    //   java -cp rijndael-java RijndaelTest
    static final String ENC_JAR = "RijndaelEncrypt.jar";
    static final String DEC_JAR = "RijndaelDecrypt.jar";

    static int passed = 0;
    static int failed = 0;

    // -----------------------------------------------------------------------
    // Mini test framework
    // -----------------------------------------------------------------------

    static void assertTrue(String label, boolean condition) {
        if (condition) {
            System.out.printf("  PASS : %s%n", label);
            passed++;
        } else {
            System.out.printf("  FAIL : %s%n", label);
            failed++;
        }
    }

    static void assertEquals(String label, Object expected, Object actual) {
        boolean eq = Objects.equals(expected, actual);
        if (!eq && expected instanceof byte[] && actual instanceof byte[]) {
            eq = Arrays.equals((byte[]) expected, (byte[]) actual);
        }
        assertTrue(label + " [expected=" + expected + " actual=" + actual + "]", eq);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    static Path createTempDir() throws IOException {
        return Files.createTempDirectory("rijndael-java-test-");
    }

    static void setupKeys(Path dir, String keyHex, String ivHex) throws IOException {
        Files.writeString(dir.resolve("input.key"), keyHex);
        Files.writeString(dir.resolve("input.iv"),  ivHex);
    }

    static ProcessResult runJar(String jar, String... args) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>();
        cmd.add("java");
        cmd.add("-jar");
        cmd.add(jar);
        cmd.addAll(Arrays.asList(args));

        Process p = new ProcessBuilder(cmd)
                .redirectErrorStream(false)
                .start();

        String stdout = new String(p.getInputStream().readAllBytes());
        String stderr = new String(p.getErrorStream().readAllBytes());
        int exitCode  = p.waitFor();
        return new ProcessResult(exitCode, stdout, stderr);
    }

    static ProcessResult encrypt(Path dir, byte[] plaintext, String keyHex, String ivHex)
            throws Exception {
        Path inFile  = dir.resolve("input.txt");
        Path outFile = dir.resolve("output.rij");
        Files.write(inFile, plaintext);
        Files.writeString(dir.resolve("input.key"), keyHex);
        Files.writeString(dir.resolve("input.iv"),  ivHex);
        return runJar(ENC_JAR,
                inFile.toString(), outFile.toString(),
                dir.resolve("input.key").toString(),
                dir.resolve("input.iv").toString());
    }

    static ProcessResult decrypt(Path dir, String keyHex, String ivHex) throws Exception {
        Path ctFile  = dir.resolve("output.rij");
        Path outFile = dir.resolve("decrypted.txt");
        Files.writeString(dir.resolve("dec.key"), keyHex);
        Files.writeString(dir.resolve("dec.iv"),  ivHex);
        return runJar(DEC_JAR,
                ctFile.toString(), outFile.toString(),
                dir.resolve("dec.key").toString(),
                dir.resolve("dec.iv").toString());
    }

    static byte[] hmacSha512(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(key, "HmacSHA512"));
        return mac.doFinal(data);
    }

    static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        return data;
    }

    static void deleteDir(Path dir) throws IOException {
        Files.walk(dir)
             .sorted(Comparator.reverseOrder())
             .forEach(p -> { try { Files.delete(p); } catch (IOException ignored) {} });
    }

    static class ProcessResult {
        final int exitCode;
        final String stdout;
        final String stderr;
        ProcessResult(int exitCode, String stdout, String stderr) {
            this.exitCode = exitCode;
            this.stdout   = stdout;
            this.stderr   = stderr;
        }
        boolean succeeded() { return exitCode == 0; }
    }

    // -----------------------------------------------------------------------
    // Encrypt tests
    // -----------------------------------------------------------------------

    static void testEncryptCreatesOutputFile() throws Exception {
        Path dir = createTempDir();
        try {
            ProcessResult r = encrypt(dir, PLAINTEXT, KEY_HEX, IV_HEX);
            assertTrue("encrypt: exit 0", r.succeeded());
            assertTrue("encrypt: output file created", Files.exists(dir.resolve("output.rij")));
        } finally { deleteDir(dir); }
    }

    static void testEncryptCreatesSigFile() throws Exception {
        Path dir = createTempDir();
        try {
            ProcessResult r = encrypt(dir, PLAINTEXT, KEY_HEX, IV_HEX);
            assertTrue("encrypt: .sig file created", Files.exists(dir.resolve("output.rij.sig")));
        } finally { deleteDir(dir); }
    }

    static void testEncryptOutputMultipleOfBlockSize() throws Exception {
        Path dir = createTempDir();
        try {
            ProcessResult r = encrypt(dir, PLAINTEXT, KEY_HEX, IV_HEX);
            if (!r.succeeded()) { assertTrue("encrypt: ciphertext length multiple of 16 [encrypt failed]", false); return; }
            long sz = Files.size(dir.resolve("output.rij"));
            assertTrue("encrypt: ciphertext length is multiple of 16", sz % 16 == 0);
        } finally { deleteDir(dir); }
    }

    static void testEncryptSigIs64Bytes() throws Exception {
        Path dir = createTempDir();
        try {
            ProcessResult r = encrypt(dir, PLAINTEXT, KEY_HEX, IV_HEX);
            if (!r.succeeded()) { assertTrue("encrypt: sig is 64 bytes [encrypt failed]", false); return; }
            long sz = Files.size(dir.resolve("output.rij.sig"));
            assertEquals("encrypt: sig is 64 bytes", 64L, sz);
        } finally { deleteDir(dir); }
    }

    static void testEncryptSigMatchesHMACSHA512() throws Exception {
        Path dir = createTempDir();
        try {
            encrypt(dir, PLAINTEXT, KEY_HEX, IV_HEX);
            byte[] key       = hexToBytes(KEY_HEX);
            byte[] ct        = Files.readAllBytes(dir.resolve("output.rij"));
            byte[] expected  = hmacSha512(key, ct);
            byte[] actual    = Files.readAllBytes(dir.resolve("output.rij.sig"));
            assertTrue("encrypt: sig matches HMAC-SHA512 of ciphertext",
                    Arrays.equals(expected, actual));
        } finally { deleteDir(dir); }
    }

    static void testEncryptPaddingLengths() throws Exception {
        int[][] cases = {
            {0, 16}, {1, 16}, {15, 16},
            {16, 32}, {17, 32}, {28, 32}, {31, 32},
            {32, 48}
        };
        for (int[] tc : cases) {
            int inputLen = tc[0], expectedLen = tc[1];
            Path dir = createTempDir();
            try {
                byte[] pt = new byte[inputLen];
                Arrays.fill(pt, (byte) 'A');
                encrypt(dir, pt, KEY_HEX, IV_HEX);
                long sz = Files.size(dir.resolve("output.rij"));
                assertTrue(
                    "encrypt: input " + inputLen + " bytes -> output " + expectedLen + " bytes",
                    sz == expectedLen
                );
            } finally { deleteDir(dir); }
        }
    }

    static void testEncryptDeterministic() throws Exception {
        Path dir1 = createTempDir(), dir2 = createTempDir();
        try {
            encrypt(dir1, PLAINTEXT, KEY_HEX, IV_HEX);
            encrypt(dir2, PLAINTEXT, KEY_HEX, IV_HEX);
            byte[] ct1 = Files.readAllBytes(dir1.resolve("output.rij"));
            byte[] ct2 = Files.readAllBytes(dir2.resolve("output.rij"));
            assertTrue("encrypt: same key/IV/plaintext -> same ciphertext", Arrays.equals(ct1, ct2));
        } finally { deleteDir(dir1); deleteDir(dir2); }
    }

    static void testEncryptDifferentIVDifferentCiphertext() throws Exception {
        Path dir1 = createTempDir(), dir2 = createTempDir();
        try {
            encrypt(dir1, PLAINTEXT, KEY_HEX, IV_HEX);
            encrypt(dir2, PLAINTEXT, KEY_HEX, WRONG_IV_HEX);
            byte[] ct1 = Files.readAllBytes(dir1.resolve("output.rij"));
            byte[] ct2 = Files.readAllBytes(dir2.resolve("output.rij"));
            assertTrue("encrypt: different IV -> different ciphertext", !Arrays.equals(ct1, ct2));
        } finally { deleteDir(dir1); deleteDir(dir2); }
    }

    static void testEncryptDifferentKeyDifferentCiphertext() throws Exception {
        Path dir1 = createTempDir(), dir2 = createTempDir();
        try {
            encrypt(dir1, PLAINTEXT, KEY_HEX, IV_HEX);
            encrypt(dir2, PLAINTEXT, WRONG_KEY_HEX, IV_HEX);
            byte[] ct1 = Files.readAllBytes(dir1.resolve("output.rij"));
            byte[] ct2 = Files.readAllBytes(dir2.resolve("output.rij"));
            assertTrue("encrypt: different key -> different ciphertext", !Arrays.equals(ct1, ct2));
        } finally { deleteDir(dir1); deleteDir(dir2); }
    }

    static void testEncryptStdoutLabel() throws Exception {
        Path dir = createTempDir();
        try {
            ProcessResult r = encrypt(dir, PLAINTEXT, KEY_HEX, IV_HEX);
            assertTrue("encrypt: stdout contains Java label",
                    r.stdout.contains("[ Java | encrypt ]"));
        } finally { deleteDir(dir); }
    }

    static void testEncryptStdoutAlgorithm() throws Exception {
        Path dir = createTempDir();
        try {
            ProcessResult r = encrypt(dir, PLAINTEXT, KEY_HEX, IV_HEX);
            assertTrue("encrypt: stdout contains algorithm name",
                    r.stdout.contains("AES-256/CBC/PKCS7"));
        } finally { deleteDir(dir); }
    }

    static void testEncryptExitOneNoArgs() throws Exception {
        ProcessResult r = runJar(ENC_JAR);
        assertEquals("encrypt: exit 1 on no args", 1, r.exitCode);
    }

    static void testEncryptExitTwoMissingInput() throws Exception {
        Path dir = createTempDir();
        try {
            setupKeys(dir, KEY_HEX, IV_HEX);
            ProcessResult r = runJar(ENC_JAR,
                    dir.resolve("nonexistent.txt").toString(),
                    dir.resolve("output.rij").toString(),
                    dir.resolve("input.key").toString(),
                    dir.resolve("input.iv").toString());
            assertTrue("encrypt: exit non-zero on missing input file", r.exitCode != 0);
        } finally { deleteDir(dir); }
    }

    // -----------------------------------------------------------------------
    // Decrypt tests
    // -----------------------------------------------------------------------

    static void testDecryptRoundtrip() throws Exception {
        Path dir = createTempDir();
        try {
            ProcessResult er = encrypt(dir, PLAINTEXT, KEY_HEX, IV_HEX);
            assertTrue("roundtrip: encrypt succeeds", er.succeeded());
            ProcessResult dr = decrypt(dir, KEY_HEX, IV_HEX);
            assertTrue("roundtrip: decrypt succeeds", dr.succeeded());
            byte[] got = Files.readAllBytes(dir.resolve("decrypted.txt"));
            assertTrue("roundtrip: plaintext recovered", Arrays.equals(PLAINTEXT, got));
        } finally { deleteDir(dir); }
    }

    static void testDecryptRoundtripEmpty() throws Exception {
        Path dir = createTempDir();
        try {
            encrypt(dir, new byte[0], KEY_HEX, IV_HEX);
            ProcessResult dr = decrypt(dir, KEY_HEX, IV_HEX);
            assertTrue("roundtrip empty: decrypt succeeds", dr.succeeded());
            byte[] got = Files.readAllBytes(dir.resolve("decrypted.txt"));
            assertTrue("roundtrip empty: output is empty", got.length == 0);
        } finally { deleteDir(dir); }
    }

    static void testDecryptRoundtripExactBlock() throws Exception {
        Path dir = createTempDir();
        byte[] pt = "1234567890abcdef".getBytes();
        try {
            encrypt(dir, pt, KEY_HEX, IV_HEX);
            ProcessResult dr = decrypt(dir, KEY_HEX, IV_HEX);
            assertTrue("roundtrip 16-byte: decrypt succeeds", dr.succeeded());
            byte[] got = Files.readAllBytes(dir.resolve("decrypted.txt"));
            assertTrue("roundtrip 16-byte: plaintext recovered", Arrays.equals(pt, got));
        } finally { deleteDir(dir); }
    }

    static void testDecryptRoundtripLarge() throws Exception {
        Path dir = createTempDir();
        byte[] pt = new byte[8192];
        for (int i = 0; i < pt.length; i++) pt[i] = (byte) (i & 0xFF);
        try {
            encrypt(dir, pt, KEY_HEX, IV_HEX);
            ProcessResult dr = decrypt(dir, KEY_HEX, IV_HEX);
            assertTrue("roundtrip large: decrypt succeeds", dr.succeeded());
            byte[] got = Files.readAllBytes(dir.resolve("decrypted.txt"));
            assertTrue("roundtrip large: plaintext recovered", Arrays.equals(pt, got));
        } finally { deleteDir(dir); }
    }

    static void testDecryptMACVerifiedInStdout() throws Exception {
        Path dir = createTempDir();
        try {
            encrypt(dir, PLAINTEXT, KEY_HEX, IV_HEX);
            ProcessResult dr = decrypt(dir, KEY_HEX, IV_HEX);
            assertTrue("decrypt: MAC verified OK in stdout",
                    dr.stdout.contains("verified OK"));
        } finally { deleteDir(dir); }
    }

    static void testDecryptTamperedCiphertextFails() throws Exception {
        Path dir = createTempDir();
        try {
            encrypt(dir, PLAINTEXT, KEY_HEX, IV_HEX);
            Path ctFile = dir.resolve("output.rij");
            byte[] ct = Files.readAllBytes(ctFile);
            ct[0] ^= (byte) 0xFF;
            Files.write(ctFile, ct);
            ProcessResult dr = decrypt(dir, KEY_HEX, IV_HEX);
            assertTrue("decrypt: tampered ciphertext causes failure", !dr.succeeded());
        } finally { deleteDir(dir); }
    }

    static void testDecryptTamperedSigFails() throws Exception {
        Path dir = createTempDir();
        try {
            encrypt(dir, PLAINTEXT, KEY_HEX, IV_HEX);
            Path sigFile = dir.resolve("output.rij.sig");
            byte[] sig = Files.readAllBytes(sigFile);
            sig[0] ^= (byte) 0xFF;
            Files.write(sigFile, sig);
            ProcessResult dr = decrypt(dir, KEY_HEX, IV_HEX);
            assertTrue("decrypt: tampered sig causes failure", !dr.succeeded());
        } finally { deleteDir(dir); }
    }

    static void testDecryptWrongKeyFails() throws Exception {
        Path dir = createTempDir();
        try {
            encrypt(dir, PLAINTEXT, KEY_HEX, IV_HEX);
            ProcessResult dr = decrypt(dir, WRONG_KEY_HEX, IV_HEX);
            assertTrue("decrypt: wrong key causes failure", !dr.succeeded());
        } finally { deleteDir(dir); }
    }

    static void testDecryptStdoutLabel() throws Exception {
        Path dir = createTempDir();
        try {
            encrypt(dir, PLAINTEXT, KEY_HEX, IV_HEX);
            ProcessResult dr = decrypt(dir, KEY_HEX, IV_HEX);
            assertTrue("decrypt: stdout contains Java label",
                    dr.stdout.contains("[ Java | decrypt ]"));
        } finally { deleteDir(dir); }
    }

    static void testDecryptExitOneNoArgs() throws Exception {
        ProcessResult r = runJar(DEC_JAR);
        assertEquals("decrypt: exit 1 on no args", 1, r.exitCode);
    }

    static void testDecryptNonzeroMissingCiphertext() throws Exception {
        Path dir = createTempDir();
        try {
            setupKeys(dir, KEY_HEX, IV_HEX);
            ProcessResult r = runJar(DEC_JAR,
                    dir.resolve("nonexistent.rij").toString(),
                    dir.resolve("out.txt").toString(),
                    dir.resolve("input.key").toString(),
                    dir.resolve("input.iv").toString());
            assertTrue("decrypt: non-zero exit on missing ciphertext", r.exitCode != 0);
        } finally { deleteDir(dir); }
    }

    // -----------------------------------------------------------------------
    // Main
    // -----------------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        System.out.println("=== RijndaelTest (Java) ===");

        System.out.println("\n-- Encrypt --");
        testEncryptCreatesOutputFile();
        testEncryptCreatesSigFile();
        testEncryptOutputMultipleOfBlockSize();
        testEncryptSigIs64Bytes();
        testEncryptSigMatchesHMACSHA512();
        testEncryptPaddingLengths();
        testEncryptDeterministic();
        testEncryptDifferentIVDifferentCiphertext();
        testEncryptDifferentKeyDifferentCiphertext();
        testEncryptStdoutLabel();
        testEncryptStdoutAlgorithm();
        testEncryptExitOneNoArgs();
        testEncryptExitTwoMissingInput();

        System.out.println("\n-- Decrypt --");
        testDecryptRoundtrip();
        testDecryptRoundtripEmpty();
        testDecryptRoundtripExactBlock();
        testDecryptRoundtripLarge();
        testDecryptMACVerifiedInStdout();
        testDecryptTamperedCiphertextFails();
        testDecryptTamperedSigFails();
        testDecryptWrongKeyFails();
        testDecryptStdoutLabel();
        testDecryptExitOneNoArgs();
        testDecryptNonzeroMissingCiphertext();

        System.out.printf("%n=== Results: %d passed, %d failed ===%n", passed, failed);
        if (failed > 0) System.exit(1);
    }
}
