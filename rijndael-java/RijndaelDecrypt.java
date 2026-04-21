import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class RijndaelDecrypt {

    private static byte[] fileRead(String fname) throws IOException {
        return Files.readAllBytes(Paths.get(fname));
    }

    private static void fileWrite(String fname, byte[] data) throws IOException {
        Files.write(Paths.get(fname), data);
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private static byte[] computeHmac(byte[] message, byte[] key) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA512");
        hmac.init(new SecretKeySpec(key, "HmacSHA512"));
        return hmac.doFinal(message);
    }

    public static void main(String[] args) {
        if (args.length != 4) {
            System.err.println("Usage: java -jar RijndaelDecrypt.jar <ifname> <ofname> <if_key> <if_iv>");
            System.exit(1);
        }

        String ifname = args[0];
        String ofname = args[1];
        String if_key = args[2];
        String if_iv  = args[3];

        File f = new File(ifname);
        if (!f.exists() || f.isDirectory()) {
            System.err.println("cannot find file: " + ifname);
            System.exit(2);
        }

        byte[] KEY = null;
        try {
            KEY = hexToBytes(new String(fileRead(if_key), StandardCharsets.US_ASCII).trim());
            byte[] IV = hexToBytes(new String(fileRead(if_iv),  StandardCharsets.US_ASCII).trim());

            System.out.println("[ Java | decrypt ] algorithm : AES-" + (KEY.length * 8) + "/CBC/PKCS7");

            byte[] cipherText = fileRead(ifname);
            System.out.println("[ Java | decrypt ] input     : " + cipherText.length + " bytes");

            // Verify MAC before decryption to prevent padding oracle attacks.
            // When no .sig file exists (e.g. ciphertext from C/Python) we warn and proceed.
            String sigFile = ifname + ".sig";
            if (new File(sigFile).exists()) {
                byte[] storedMac   = fileRead(sigFile);
                byte[] computedMac = computeHmac(cipherText, KEY);
                if (!MessageDigest.isEqual(storedMac, computedMac)) {
                    System.err.println("ABORT: MAC verification failed — ciphertext has been tampered with");
                    System.exit(3);
                }
                System.out.println("[ Java | decrypt ] MAC       : verified OK");
            } else {
                System.out.println("[ Java | decrypt ] WARNING   : no .sig file — skipping MAC verification");
            }

            SecretKeySpec secretKey = new SecretKeySpec(KEY, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));
            byte[] plainText = cipher.doFinal(cipherText);
            fileWrite(ofname, plainText);
            System.out.println("[ Java | decrypt ] output    : " + ofname);

        } catch (java.security.InvalidKeyException e) {
            System.err.println("ABORT: InvalidKeyException — key must be 16, 24, or 32 bytes");
            System.exit(4);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(5);
        } finally {
            if (KEY != null) Arrays.fill(KEY, (byte) 0);
        }
    }
}
