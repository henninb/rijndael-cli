#!/usr/bin/env groovy
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
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
    System.err.println("Usage: rijndael-decrypt.groovy <ifname> <ofname> <keyfname> <ivfname>")
    System.exit(1)
}

def (ifname, ofname, keyfname, ivfname) = args

byte[] key = hexToBytes(new File(keyfname).getText(StandardCharsets.US_ASCII.name()).trim())
byte[] iv  = hexToBytes(new File(ivfname).getText(StandardCharsets.US_ASCII.name()).trim())

println "[ Groovy | decrypt ] algorithm : AES-${key.length * 8}/CBC/PKCS7"

byte[] cipherText = new File(ifname).bytes
println "[ Groovy | decrypt ] input     : ${cipherText.length} bytes"

File sigFile = new File("${ifname}.sig")
if (sigFile.exists()) {
    byte[] storedMac   = sigFile.bytes
    byte[] computedMac = computeHmac(cipherText, key)
    if (!MessageDigest.isEqual(storedMac, computedMac)) {
        System.err.println("ABORT: MAC verification failed — ciphertext has been tampered with")
        System.exit(3)
    }
    println "[ Groovy | decrypt ] MAC       : verified OK"
} else {
    println "[ Groovy | decrypt ] WARNING   : no .sig file — skipping MAC verification"
}

SecretKeySpec secretKey = new SecretKeySpec(key, 'AES')
Cipher cipher = Cipher.getInstance('AES/CBC/PKCS5Padding')
cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv))

byte[] plainText = cipher.doFinal(cipherText)
new File(ofname).bytes = plainText
println "[ Groovy | decrypt ] output    : ${ofname}"
