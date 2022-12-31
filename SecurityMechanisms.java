package MigrationModel;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.util.encoders.Base64Encoder;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Base64;


public class SecurityMechanisms {

    //public static String SECRET_KEY;
    public static final String SALT = "ssshhhhhhhhhhh!!!!ssshhhhhhhhhhh!!!!";
    //public static int AES_Key_Length;
    public static String AES_cipher_setting;

    public static String SECRET_KEY_BF;

    public static String SECRET_KEY_RC4 = "ThisIsTheRC4SecretKey";


    public static String HASH_ALGO = "SHA-512";
    public static int Keccak_Key_Length = 256;

    private static final String STREAM_ENCRYPTION_ALGORITHM = "ARCFOUR"; // or "RC4"


    //////////////////////////////////////////      AES         //////////////////////////////////////////////////

    public static String AES_Encrypt(String strToEncrypt, String SECRET_KEY, int AES_Key_Length) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, AES_Key_Length);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            //Cipher cipher = Cipher.getInstance(AES_cipher_setting);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            //Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            //Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            //Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            //Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
            //Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            //cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder()
                    .encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String AES_Decrypt(String strToDecrypt, String SECRET_KEY, int AES_Key_Length) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, AES_Key_Length);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            //Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            //Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            //Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            //Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
            //Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            //cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    /////////////////////////////////////       RC4         //////////////////////////////////////////////////////////////
    public static byte[] RC4_encrypt(String plaintext) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {

        KeyGenerator rc4KeyGenerator = KeyGenerator.getInstance(STREAM_ENCRYPTION_ALGORITHM);
        SecretKey secretKey = rc4KeyGenerator.generateKey();
        Cipher rc4 = Cipher.getInstance(STREAM_ENCRYPTION_ALGORITHM);

        rc4.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] ciphertextBytes = rc4.doFinal(plaintextBytes);
        //System.out.println("RC4 ciphertext base64 encoded: " + Base64.encodeBase64String(ciphertextBytes));
        return ciphertextBytes;
    }

    public static byte[] RC4_decrypt(byte[] ciphertextBytes) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {

        KeyGenerator rc4KeyGenerator = KeyGenerator.getInstance(STREAM_ENCRYPTION_ALGORITHM);
        SecretKey secretKey = rc4KeyGenerator.generateKey();
        Cipher rc4 = Cipher.getInstance(STREAM_ENCRYPTION_ALGORITHM);
        rc4.init(Cipher.DECRYPT_MODE, secretKey, rc4.getParameters());
        byte[] byteDecryptedText = rc4.doFinal(ciphertextBytes);
        return  byteDecryptedText;
        //String plaintextBack = new String(byteDecryptedText);
        //System.out.println("Decrypted back to: " + plaintextBack);
    }


    public static String RC4Encrypt(String value, byte[] key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {

            final Cipher rc4 = Cipher.getInstance("ARCFOUR");
            rc4.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ARCFOUR"));
            return Base64.getEncoder().encodeToString(rc4.doFinal(value.getBytes()));

    }

    public static String RC4Decrypt(String value, byte[] key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {

        final Cipher rc4 = Cipher.getInstance("ARCFOUR");
        rc4.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ARCFOUR"));
        return new String(rc4.doFinal(Base64.getDecoder().decode(value)));

    }
    ///////////////////////////////         SHA HASH        /////////////////////////////////////////////////////////////

    public static String Hash (String message) throws NoSuchAlgorithmException {
        // getInstance() method is called with algorithm SHA-512
        MessageDigest md = MessageDigest.getInstance(HASH_ALGO);

        // digest() method is called
        // to calculate message digest of the input string
        // returned as array of byte
        byte[] messageDigest = md.digest(message.getBytes());

        // Convert byte array into signum representation
        BigInteger no = new BigInteger(1, messageDigest);

        // Convert message digest into hex value
        String hashtext = no.toString(16);

        // Add preceding 0s to make it 32 bit
        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }

        // return the HashText
        return hashtext;
    }


    /////////////////////////////       BlowFish        ///////////////////////////////////////////////////////////////////
    public static String BF_encrypt(String password, String key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        byte[] KeyData = key.getBytes();
        SecretKeySpec KS = new SecretKeySpec(KeyData, "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.ENCRYPT_MODE, KS);
        String encryptedtext = Base64.getEncoder().encodeToString(cipher.doFinal(password.getBytes("UTF-8")));
        return encryptedtext;

    }

    public static String BF_decrypt(String encryptedtext, String key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] KeyData = key.getBytes();
        SecretKeySpec KS = new SecretKeySpec(KeyData, "Blowfish");
        byte[] ecryptedtexttobytes = Base64.getDecoder().
                decode(encryptedtext);
        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.DECRYPT_MODE, KS);
        byte[] decrypted = cipher.doFinal(ecryptedtexttobytes);
        String decryptedString = new String(decrypted, Charset.forName("UTF-8"));
        return decryptedString;

    }

    //////////////////////      BOUNCY CASTLE       ////////////////////////////////
    public static String hashKeccak(String data) {
        byte[] dataBytes = data.getBytes();
        Keccak.DigestKeccak md = new Keccak.DigestKeccak(Keccak_Key_Length);
        md.reset();
        md.update(dataBytes, 0, dataBytes.length);
        byte[] hashedBytes = md.digest();
        BigInteger no = new BigInteger(1, hashedBytes);
        String hashtext = no.toString(16);
        return hashtext;
    }





}
