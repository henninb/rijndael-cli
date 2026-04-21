using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class RijndaelEncrypt {

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

    byte[] KEY = hexStringToByteArray(Encoding.ASCII.GetString(fileReadBytes(key_fname)).Trim());
    byte[] IV  = hexStringToByteArray(Encoding.ASCII.GetString(fileReadBytes(iv_fname)).Trim());

    byte[] cipherBytes = rijndael_encrypt(fileReadBytes(ifname), ofname, KEY, IV);

    using HMACSHA512 hmac = new HMACSHA512(KEY);
    byte[] signature = hmac.ComputeHash(cipherBytes);
    fileWrite(ofname + ".sig", signature);
    Console.WriteLine("[ C# | encrypt ] signature : written");

    Array.Clear(KEY, 0, KEY.Length);
  }

  public static byte[] hexStringToByteArray( string s ) {
    int len = s.Length;
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2)
      data[i / 2] = (byte)((Convert.ToInt32(s[i].ToString(), 16) << 4) + Convert.ToInt32(s[i + 1].ToString(), 16));
    return data;
  }

  private static void fileWrite( string fileName, byte[] message ) {
    using FileStream fs = new FileStream(fileName, FileMode.Create, FileAccess.Write, FileShare.None);
    fs.Write(message, 0, message.Length);
  }

  private static byte[] fileReadBytes( string fname ) {
    try { return File.ReadAllBytes(fname); }
    catch (Exception e) { Console.Error.WriteLine("ABORT: " + e.Message); Environment.Exit(1); return null; }
  }

  public static byte[] rijndael_encrypt( byte[] plainBytes, string ofname, byte[] KEY, byte[] IV ) {
    using RijndaelManaged rijndael = new RijndaelManaged();
    rijndael.Key       = KEY;
    rijndael.IV        = IV;
    rijndael.Mode      = CipherMode.CBC;
    rijndael.KeySize   = 256;
    rijndael.BlockSize = 128;

    Console.WriteLine("[ C# | encrypt ] algorithm : AES-" + rijndael.KeySize + "/CBC/PKCS7");

    using ICryptoTransform encryptor = rijndael.CreateEncryptor(KEY, IV);
    using MemoryStream ms = new MemoryStream();
    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write)) {
      cs.Write(plainBytes, 0, plainBytes.Length);
      cs.FlushFinalBlock();
    }
    byte[] cipherBytes = ms.ToArray();
    Console.WriteLine("[ C# | encrypt ] input     : " + plainBytes.Length + " bytes  ->  padded : " + cipherBytes.Length + " bytes");
    fileWrite(ofname, cipherBytes);
    Console.WriteLine("[ C# | encrypt ] output    : " + ofname);
    return cipherBytes;
  }
}
