using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

/// <summary>
/// Integration tests for rijndael-mono-encrypt.exe / rijndael-mono-decrypt.exe.
///
/// Run from project root:
///   dotnet test rijndael-csharp/RijndaelTests/RijndaelTests.csproj
///
/// Requires binaries to be built first (make linux).
/// </summary>
public class RijndaelTests
{
    const string KeyHex      = "594193e330c8e8312f244c9cff045b73e66c301c30eb3bf0ec943a25e7a45650";
    const string IvHex       = "2cef85f5259ae311034de17fda3b8369";
    const string WrongKeyHex = "0000000000000000000000000000000000000000000000000000000000000000";
    const string WrongIvHex  = "ffffffffffffffffffffffffffffffff";

    static readonly byte[] Plaintext = System.Text.Encoding.UTF8.GetBytes("my message to you, let's win");

    static readonly string ProjectRoot = Path.GetFullPath(
        Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    static string EncBin => Path.Combine(ProjectRoot, "rijndael-mono-encrypt.exe");
    static string DecBin => Path.Combine(ProjectRoot, "rijndael-mono-decrypt.exe");

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "rijndael-cs-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void SetupKeys(string dir, string keyHex = KeyHex, string ivHex = IvHex)
    {
        File.WriteAllText(Path.Combine(dir, "input.key"), keyHex);
        File.WriteAllText(Path.Combine(dir, "input.iv"),  ivHex);
    }

    private static (int ExitCode, string Stdout, string Stderr) Run(string bin, params string[] args)
    {
        using var proc = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName               = bin,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
            }
        };
        foreach (var a in args) proc.StartInfo.ArgumentList.Add(a);
        proc.Start();
        string stdout = proc.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        return (proc.ExitCode, stdout, stderr);
    }

    private static (int ExitCode, string Stdout, string Stderr) Encrypt(
        string dir, byte[]? pt = null, string? keyHex = null, string? ivHex = null)
    {
        pt ??= Plaintext;
        var keyFile = Path.Combine(dir, "input.key");
        var ivFile  = Path.Combine(dir, "input.iv");
        File.WriteAllText(keyFile, keyHex ?? KeyHex);
        File.WriteAllText(ivFile,  ivHex  ?? IvHex);
        var inputFile  = Path.Combine(dir, "input.txt");
        var outputFile = Path.Combine(dir, "output.rij");
        File.WriteAllBytes(inputFile, pt);
        return Run(EncBin, inputFile, outputFile, keyFile, ivFile);
    }

    private static (int ExitCode, string Stdout, string Stderr) Decrypt(
        string dir, string? keyHex = null, string? ivHex = null)
    {
        var ctFile  = Path.Combine(dir, "output.rij");
        var outFile = Path.Combine(dir, "decrypted.txt");
        var keyFile = Path.Combine(dir, "dec.key");
        var ivFile  = Path.Combine(dir, "dec.iv");
        File.WriteAllText(keyFile, keyHex ?? KeyHex);
        File.WriteAllText(ivFile,  ivHex  ?? IvHex);
        return Run(DecBin, ctFile, outFile, keyFile, ivFile);
    }

    private static byte[] HexToBytes(string hex)
    {
        var result = new byte[hex.Length / 2];
        for (int i = 0; i < hex.Length; i += 2)
            result[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        return result;
    }

    // -----------------------------------------------------------------------
    // Encrypt – output structure
    // -----------------------------------------------------------------------

    [Fact]
    public void Encrypt_CreatesOutputFile()
    {
        string dir = TempDir();
        try
        {
            var (code, _, _) = Encrypt(dir);
            Assert.Equal(0, code);
            Assert.True(File.Exists(Path.Combine(dir, "output.rij")));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Encrypt_CreatesSigFile()
    {
        string dir = TempDir();
        try
        {
            Encrypt(dir);
            Assert.True(File.Exists(Path.Combine(dir, "output.rij.sig")));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Encrypt_OutputIsMultipleOfBlockSize()
    {
        string dir = TempDir();
        try
        {
            Encrypt(dir);
            long sz = new FileInfo(Path.Combine(dir, "output.rij")).Length;
            Assert.Equal(0L, sz % 16);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Encrypt_SigIs64Bytes()
    {
        string dir = TempDir();
        try
        {
            Encrypt(dir);
            long sz = new FileInfo(Path.Combine(dir, "output.rij.sig")).Length;
            Assert.Equal(64L, sz);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Encrypt_SigMatchesHmacSha512()
    {
        string dir = TempDir();
        try
        {
            Encrypt(dir);
            byte[] key = HexToBytes(KeyHex);
            byte[] ct  = File.ReadAllBytes(Path.Combine(dir, "output.rij"));
            using var hmac = new HMACSHA512(key);
            byte[] expected = hmac.ComputeHash(ct);
            byte[] actual   = File.ReadAllBytes(Path.Combine(dir, "output.rij.sig"));
            Assert.Equal(expected, actual);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    // -----------------------------------------------------------------------
    // Encrypt – PKCS7 padding
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData(0,  16)]
    [InlineData(1,  16)]
    [InlineData(15, 16)]
    [InlineData(16, 32)]
    [InlineData(17, 32)]
    [InlineData(28, 32)]
    [InlineData(31, 32)]
    [InlineData(32, 48)]
    public void Encrypt_PaddingLength(int inputLen, int expectedOutputLen)
    {
        string dir = TempDir();
        try
        {
            Encrypt(dir, pt: new byte[inputLen]);
            long sz = new FileInfo(Path.Combine(dir, "output.rij")).Length;
            Assert.Equal(expectedOutputLen, sz);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    // -----------------------------------------------------------------------
    // Encrypt – determinism and sensitivity
    // -----------------------------------------------------------------------

    [Fact]
    public void Encrypt_DeterministicWithSameKeyIv()
    {
        string dir1 = TempDir(), dir2 = TempDir();
        try
        {
            Encrypt(dir1);
            Encrypt(dir2);
            byte[] ct1 = File.ReadAllBytes(Path.Combine(dir1, "output.rij"));
            byte[] ct2 = File.ReadAllBytes(Path.Combine(dir2, "output.rij"));
            Assert.Equal(ct1, ct2);
        }
        finally
        {
            Directory.Delete(dir1, recursive: true);
            Directory.Delete(dir2, recursive: true);
        }
    }

    [Fact]
    public void Encrypt_DifferentIvGivesDifferentCiphertext()
    {
        string dir1 = TempDir(), dir2 = TempDir();
        try
        {
            Encrypt(dir1);
            Encrypt(dir2, ivHex: WrongIvHex);
            byte[] ct1 = File.ReadAllBytes(Path.Combine(dir1, "output.rij"));
            byte[] ct2 = File.ReadAllBytes(Path.Combine(dir2, "output.rij"));
            Assert.NotEqual(ct1, ct2);
        }
        finally
        {
            Directory.Delete(dir1, recursive: true);
            Directory.Delete(dir2, recursive: true);
        }
    }

    [Fact]
    public void Encrypt_DifferentKeyGivesDifferentCiphertext()
    {
        string dir1 = TempDir(), dir2 = TempDir();
        try
        {
            Encrypt(dir1);
            Encrypt(dir2, keyHex: WrongKeyHex);
            byte[] ct1 = File.ReadAllBytes(Path.Combine(dir1, "output.rij"));
            byte[] ct2 = File.ReadAllBytes(Path.Combine(dir2, "output.rij"));
            Assert.NotEqual(ct1, ct2);
        }
        finally
        {
            Directory.Delete(dir1, recursive: true);
            Directory.Delete(dir2, recursive: true);
        }
    }

    // -----------------------------------------------------------------------
    // Encrypt – stdout messages
    // -----------------------------------------------------------------------

    [Fact]
    public void Encrypt_StdoutContainsLanguageLabel()
    {
        string dir = TempDir();
        try
        {
            var (_, stdout, _) = Encrypt(dir);
            Assert.Contains("[ C# | encrypt ]", stdout);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Encrypt_StdoutContainsAlgorithmName()
    {
        string dir = TempDir();
        try
        {
            var (_, stdout, _) = Encrypt(dir);
            Assert.Contains("AES-256/CBC/PKCS7", stdout);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    // -----------------------------------------------------------------------
    // Encrypt – error handling
    // -----------------------------------------------------------------------

    [Fact]
    public void Encrypt_ExitOneOnNoArgs()
    {
        var (code, _, _) = Run(EncBin);
        Assert.Equal(1, code);
    }

    [Fact]
    public void Encrypt_NonzeroOnMissingInputFile()
    {
        string dir = TempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "input.key"), KeyHex);
            File.WriteAllText(Path.Combine(dir, "input.iv"),  IvHex);
            var (code, _, _) = Run(EncBin,
                Path.Combine(dir, "nonexistent.txt"),
                Path.Combine(dir, "output.rij"),
                Path.Combine(dir, "input.key"),
                Path.Combine(dir, "input.iv"));
            Assert.NotEqual(0, code);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    // -----------------------------------------------------------------------
    // Decrypt – roundtrip
    // -----------------------------------------------------------------------

    [Fact]
    public void Decrypt_Roundtrip_Basic()
    {
        string dir = TempDir();
        try
        {
            var (ec1, _, _) = Encrypt(dir);
            Assert.Equal(0, ec1);
            var (ec2, _, _) = Decrypt(dir);
            Assert.Equal(0, ec2);
            byte[] got = File.ReadAllBytes(Path.Combine(dir, "decrypted.txt"));
            Assert.Equal(Plaintext, got);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Decrypt_Roundtrip_EmptyInput()
    {
        string dir = TempDir();
        try
        {
            Encrypt(dir, pt: Array.Empty<byte>());
            var (ec, _, _) = Decrypt(dir);
            Assert.Equal(0, ec);
            byte[] got = File.ReadAllBytes(Path.Combine(dir, "decrypted.txt"));
            Assert.Empty(got);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Decrypt_Roundtrip_ExactBlock()
    {
        string dir = TempDir();
        byte[] pt = System.Text.Encoding.ASCII.GetBytes("1234567890abcdef");
        try
        {
            Encrypt(dir, pt: pt);
            var (ec, _, _) = Decrypt(dir);
            Assert.Equal(0, ec);
            byte[] got = File.ReadAllBytes(Path.Combine(dir, "decrypted.txt"));
            Assert.Equal(pt, got);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Decrypt_Roundtrip_LargeInput()
    {
        string dir = TempDir();
        byte[] pt = Enumerable.Range(0, 8192).Select(i => (byte)(i & 0xFF)).ToArray();
        try
        {
            Encrypt(dir, pt: pt);
            var (ec, _, _) = Decrypt(dir);
            Assert.Equal(0, ec);
            byte[] got = File.ReadAllBytes(Path.Combine(dir, "decrypted.txt"));
            Assert.Equal(pt, got);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    // -----------------------------------------------------------------------
    // Decrypt – MAC verification
    // -----------------------------------------------------------------------

    [Fact]
    public void Decrypt_MacVerifiedInStdout()
    {
        string dir = TempDir();
        try
        {
            Encrypt(dir);
            var (ec, stdout, _) = Decrypt(dir);
            Assert.Equal(0, ec);
            Assert.Contains("verified OK", stdout);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Decrypt_TamperedCiphertextFails()
    {
        string dir = TempDir();
        try
        {
            Encrypt(dir);
            string ctPath = Path.Combine(dir, "output.rij");
            byte[] ct = File.ReadAllBytes(ctPath);
            ct[0] ^= 0xFF;
            File.WriteAllBytes(ctPath, ct);
            var (ec, _, _) = Decrypt(dir);
            Assert.NotEqual(0, ec);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Decrypt_TamperedSigFails()
    {
        string dir = TempDir();
        try
        {
            Encrypt(dir);
            string sigPath = Path.Combine(dir, "output.rij.sig");
            byte[] sig = File.ReadAllBytes(sigPath);
            sig[0] ^= 0xFF;
            File.WriteAllBytes(sigPath, sig);
            var (ec, _, _) = Decrypt(dir);
            Assert.NotEqual(0, ec);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Decrypt_WrongKeyFails()
    {
        string dir = TempDir();
        try
        {
            Encrypt(dir);
            var (ec, _, _) = Decrypt(dir, keyHex: WrongKeyHex);
            Assert.NotEqual(0, ec);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    // -----------------------------------------------------------------------
    // Decrypt – stdout messages
    // -----------------------------------------------------------------------

    [Fact]
    public void Decrypt_StdoutContainsLanguageLabel()
    {
        string dir = TempDir();
        try
        {
            Encrypt(dir);
            var (_, stdout, _) = Decrypt(dir);
            Assert.Contains("[ C# | decrypt ]", stdout);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    // -----------------------------------------------------------------------
    // Decrypt – error handling
    // -----------------------------------------------------------------------

    [Fact]
    public void Decrypt_ExitOneOnNoArgs()
    {
        var (code, _, _) = Run(DecBin);
        Assert.Equal(1, code);
    }

    [Fact]
    public void Decrypt_NonzeroOnMissingCiphertextFile()
    {
        string dir = TempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "input.key"), KeyHex);
            File.WriteAllText(Path.Combine(dir, "input.iv"),  IvHex);
            var (code, _, _) = Run(DecBin,
                Path.Combine(dir, "nonexistent.rij"),
                Path.Combine(dir, "out.txt"),
                Path.Combine(dir, "input.key"),
                Path.Combine(dir, "input.iv"));
            Assert.NotEqual(0, code);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }
}
