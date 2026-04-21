import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class RijndaelEncrypt {

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
            System.err.println("Usage: java -jar RijndaelEncrypt.jar <ifname> <ofname> <if_key> <if_iv>");
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
            byte[] IV  = hexToBytes(new String(fileRead(if_iv),  StandardCharsets.US_ASCII).trim());

            System.out.println("[ Java | encrypt ] algorithm : AES-" + (KEY.length * 8) + "/CBC/PKCS7");

            SecretKeySpec secretKey = new SecretKeySpec(KEY, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV));

            byte[] plainText  = fileRead(ifname);
            byte[] cipherText = cipher.doFinal(plainText);
            System.out.println("[ Java | encrypt ] input     : " + plainText.length + " bytes  ->  padded : " + cipherText.length + " bytes");
            fileWrite(ofname, cipherText);
            System.out.println("[ Java | encrypt ] output    : " + ofname);

            byte[] mac = computeHmac(cipherText, KEY);
            fileWrite(ofname + ".sig", mac);
            System.out.println("[ Java | encrypt ] signature : written");

        } catch (java.security.InvalidKeyException e) {
            System.err.println("ABORT: InvalidKeyException — key must be 16, 24, or 32 bytes");
            System.exit(3);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(4);
        } finally {
            if (KEY != null) Arrays.fill(KEY, (byte) 0);
        }
    }
}
