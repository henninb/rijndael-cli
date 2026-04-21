using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class RijndaelDecrypt {

  public static void Main( string[] args ) {
    if ( args.Length != 4 ) {
      Console.Error.WriteLine("Usage: " + Environment.GetCommandLineArgs()[0] + " <ifname> <ofname> <key> <iv>");
      Environment.Exit(1);
    }

    string ifname    = args[0];
    string ofname    = args[1];
    string key_fname = args[2];
    string iv_fname  = args[3];

    if( !File.Exists(ifname) ) {
      Console.Error.WriteLine("ABORT: input file not found: " + ifname);
      Environment.Exit(2);
    }

    byte[] KEY        = hexStringToByteArray(Encoding.ASCII.GetString(fileReadBytes(key_fname)).Trim());
    byte[] IV         = hexStringToByteArray(Encoding.ASCII.GetString(fileReadBytes(iv_fname)).Trim());
    byte[] ciphertext = fileReadBytes(ifname);

    Console.WriteLine("[ C# | decrypt ] algorithm : AES-256/CBC/PKCS7");
    Console.WriteLine("[ C# | decrypt ] input     : " + ciphertext.Length + " bytes");

    string sigFile = ifname + ".sig";
    if (File.Exists(sigFile)) {
      byte[] storedMac = fileReadBytes(sigFile);
      using HMACSHA512 hmac = new HMACSHA512(KEY);
      byte[] computedMac = hmac.ComputeHash(ciphertext);
      if (!CryptographicOperations.FixedTimeEquals(storedMac, computedMac)) {
        Console.Error.WriteLine("ABORT: MAC verification failed");
        Environment.Exit(1);
      }
      Console.WriteLine("[ C# | decrypt ] MAC       : verified OK");
    } else {
      Console.WriteLine("[ C# | decrypt ] WARNING   : no .sig file — skipping MAC verification");
    }

    rijndael_decrypt(ciphertext, ofname, KEY, IV);
    Array.Clear(KEY, 0, KEY.Length);
  }

  public static byte[] hexStringToByteArray( string s ) {
    int len = s.Length;
    byte[] data = new byte[len / 2];
    for (int idx = 0; idx < len; idx += 2)
      data[idx / 2] = (byte)((Convert.ToInt32(s[idx].ToString(), 16) << 4) + Convert.ToInt32(s[idx + 1].ToString(), 16));
    return data;
  }

  public static void rijndael_decrypt( byte[] cipher, string ofname, byte[] KEY, byte[] IV ) {
    using Rijndael rijndael = Rijndael.Create();
    rijndael.Key     = KEY;
    rijndael.IV      = IV;
    rijndael.Padding = PaddingMode.PKCS7;

    using MemoryStream ms = new MemoryStream();
    using (CryptoStream cs = new CryptoStream(ms, rijndael.CreateDecryptor(), CryptoStreamMode.Write)) {
      cs.Write(cipher, 0, cipher.Length);
      cs.Close();
    }
    byte[] plainBytes = ms.ToArray();
    using FileStream fs = new FileStream(ofname, FileMode.Create, FileAccess.Write, FileShare.None);
    fs.Write(plainBytes, 0, plainBytes.Length);
    Console.WriteLine("[ C# | decrypt ] output    : " + ofname);
  }

  private static byte[] fileReadBytes( string fname ) {
    try { return File.ReadAllBytes(fname); }
    catch (Exception e) { Console.Error.WriteLine("ABORT: " + e.Message); Environment.Exit(1); return null; }
  }
}
