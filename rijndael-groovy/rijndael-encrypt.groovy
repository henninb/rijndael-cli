#!/usr/bin/env groovy
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

static byte[] hexToBytes(String hex) {
    int len = hex.length()
    byte[] data = new byte[len.intdiv(2)]
    for (int i = 0; i < len; i += 2) {
        data[i.intdiv(2)] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                  + Character.digit(hex.charAt(i + 1), 16))
    }
    data
}

static byte[] computeHmac(byte[] message, byte[] key) {
    Mac hmac = Mac.getInstance('HmacSHA512')
    hmac.init(new SecretKeySpec(key, 'HmacSHA512'))
    hmac.doFinal(message)
}

if (args.length != 4) {
    System.err.println("Usage: rijndael-encrypt.groovy <ifname> <ofname> <keyfname> <ivfname>")
    System.exit(1)
}

def (ifname, ofname, keyfname, ivfname) = args

byte[] key = hexToBytes(new File(keyfname).getText(StandardCharsets.US_ASCII.name()).trim())
byte[] iv  = hexToBytes(new File(ivfname).getText(StandardCharsets.US_ASCII.name()).trim())

println "[ Groovy | encrypt ] algorithm : AES-${key.length * 8}/CBC/PKCS7"

SecretKeySpec secretKey = new SecretKeySpec(key, 'AES')
Cipher cipher = Cipher.getInstance('AES/CBC/PKCS5Padding')
cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv))

byte[] plainText  = new File(ifname).bytes
byte[] cipherText = cipher.doFinal(plainText)
println "[ Groovy | encrypt ] input     : ${plainText.length} bytes  ->  padded : ${cipherText.length} bytes"
new File(ofname).bytes = cipherText
println "[ Groovy | encrypt ] output    : ${ofname}"

byte[] mac = computeHmac(cipherText, key)
new File("${ofname}.sig").bytes = mac
println "[ Groovy | encrypt ] signature : written"
