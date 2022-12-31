package MigrationModel;

import org.bouncycastle.jcajce.provider.digest.Keccak;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.sql.Timestamp;
import java.util.Base64;

public class SPLayer {

    public static int LayerIndex;
    public String TUNNEL_TAG;
    public String ALGORITHM;
    public int KEY_SIZE;
    public String PADDING_SCHEME;
    public int PADDING_SIZE;
    public int I_A_VERSION;
    public int DIGEST_SIZE;
    public Timestamp TS;
    public Long SA_LifeTime;
    public Long ClockSkew;
    public boolean DoS_Puzzle_Enabled = false;
    public String PROTOCOL;

    public static String SECRET_KEY;
    public static final String SALT = "ssshhhhhhhhhhh!!!!ssshhhhhhhhhhh!!!!";
    public static int AES_Key_Length;
    public static String AES_cipher_setting;

    public static String SECRET_KEY_BF;

    public static String HASH_ALGO;
    public static int Keccak_Key_Length;

    public static String SELECTED_ALGO;


    public SPLayer(int index, String ALGO, int KEY_SIZE, String BCM, String PADDING, String KEY){

        LayerIndex = index;

        get_ALGO(ALGO,KEY_SIZE,BCM,PADDING,KEY);
        System.out.println("Security Profile Layer Registered Successfully.....\n\n");

    }

    public void get_ALGO(String ALGO, int KEY_SIZE, String BCM, String PADDING, String KEY){


        switch(ALGO){

            case "AES":
                AES_Key_Length = KEY_SIZE;
                AES_cipher_setting = "AES/"+BCM+"/"+PADDING;
                SECRET_KEY = KEY;
                SELECTED_ALGO = "AES";
                break;

            case "RSA":

            case "BF":
                SECRET_KEY_BF = KEY;
                SELECTED_ALGO = "BF";
                break;

            case "kyber":

            case "SHA":
                HASH_ALGO = "SHA-"+KEY_SIZE;
                SELECTED_ALGO = "SHA";
                break;

            case "Keccak":

                Keccak_Key_Length = KEY_SIZE;
                SELECTED_ALGO = "Keccak";
                break;

        }

    }

    public String encrypt_ALGO(String Plaintext) throws NoSuchPaddingException,NoSuchAlgorithmException,InvalidKeyException,IllegalBlockSizeException,BadPaddingException,UnsupportedEncodingException{

        String Ciphertext = null;

        switch(SELECTED_ALGO){

            case "AES":
                Ciphertext = AES_Encrypt(Plaintext);
                break;

            case "RSA":

            case "BF":
                Ciphertext = BF_encrypt(Plaintext,SECRET_KEY_BF);
                break;

            case "kyber":

            case "SHA":
                Ciphertext = Hash(Plaintext);
                break;

            case "Keccak":

                Ciphertext = hashKeccak(Plaintext);
                break;

        }
        return  Ciphertext;

    }

    public String decrypt_ALGO(String Ciphertext) throws NoSuchPaddingException,NoSuchAlgorithmException,InvalidKeyException,IllegalBlockSizeException,BadPaddingException,UnsupportedEncodingException{

        String Plaintext = null;

        switch(SELECTED_ALGO){

            case "AES":
                Plaintext = AES_Decrypt(Ciphertext);
                break;

            case "RSA":

            case "BF":
                Plaintext = BF_decrypt(Ciphertext,SECRET_KEY_BF);
                break;

            case "kyber":

        }

        return  Plaintext;

    }





    public static String AES_Encrypt(String strToEncrypt) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, AES_Key_Length);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance(AES_cipher_setting);
            //Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
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

    public static String AES_Decrypt(String strToDecrypt) {
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

    public String BF_encrypt(String password, String key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        byte[] KeyData = key.getBytes();
        SecretKeySpec KS = new SecretKeySpec(KeyData, "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.ENCRYPT_MODE, KS);
        String encryptedtext = Base64.getEncoder().encodeToString(cipher.doFinal(password.getBytes("UTF-8")));
        return encryptedtext;

    }

    public String BF_decrypt(String encryptedtext, String key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
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
        return new String(hashedBytes);
    }



}
