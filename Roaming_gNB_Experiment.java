package MigrationModel;

//import com.swiftcryptollc.crypto.provider.KyberJCE;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.Random;
import java.nio.ByteBuffer;

import static MigrationModel.Source_gNB_Experiment.Attempt;


public class Roaming_gNB_Experiment {


    public static String Plaintext;
    public static String encryptedString;
    public static int PlaintextLength = 10; //bytes
    public static int RSA_Key_length = 4096;
    public static int AES_Key_Length = 256;

    public static int aes;
    public static int aes_stream[];
    public static float des;
    public static BigInteger rsa;
    public static long Hash;
    public static double BF;
    public static char Keccak;
    public static boolean kyber;

    public static int PORT = 9000;

    public static long Start_time;
    public static long End_time;
    public static Long Process_time;
    public static long Received_time;
    public static long Sending_time;
    public static long File_Send_Start_time;
    public static long File_Send_End_time;
    public static long File_Receive_Start_time;
    public static long File_Receive_End_time;
    public static Long Process_time_Send;
    public static Long Process_time_Receive;

    public KeyFactory keyFactory;
    public PrivateKey privateKey = null;
    public PublicKey publicKey = null;



    public static String input;


    //Secret Key for DES
    public static final String SECRET_KEY_DES = "5oquil2oo2vb63e8ionujny6";

    //Secret Key for BF
    public static final String SECRET_KEY_BF = "5oquil2oo2vb63e8ionujny65oquil2oo2vb63e8ionujny6";


    //Secret Key and Salt for the AESEncrypt() and AESDecrypt() Functions
    public static final String SECRET_KEY = "my_super_secret_key_ho_ho_ho";
    public static final String SALT = "ssshhhhhhhhhhh!!!!ssshhhhhhhhhhh!!!!";

    public static int Attempt_Limit = 102;

    public static int Received_instance = 0;
    public static Long[] ProcessTime;
    public static Long Total_PT;

    public static DataOutputStream dataOutputStream = null;
    public static DataInputStream dataInputStream = null;


    public Roaming_gNB_Experiment()throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, Exception{



        ProcessTime =  new Long[Attempt_Limit];
        Total_PT = new Long("0");



        //////////////////////////////     SECURITY EXPERIMENTS        ////////////////////////////

        ServerSocket serverSocket = new ServerSocket(PORT);

        try {

            while (true) {

                Socket socket = serverSocket.accept();

                try {

                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                    encryptedString = in.readLine();

                    Received_time = System.nanoTime();

                    System.out.println(Attempt);

                    System.out.println("Received Message : "+encryptedString);

                    System.out.println("Message Received time [ns] : "+Received_time);


                    //AES Constructor
                    Roaming_gNB_Experiment gNBr_AES = new Roaming_gNB_Experiment(aes);

                    //AES GCM Stream Constructor
                    //Roaming_gNB_Experiment gNBr_AES_stream = new Roaming_gNB_Experiment(aes_stream);

                    //BlowFish Constructor
                    //Roaming_gNB_Experiment gNBr_BF = new Roaming_gNB_Experiment(BF);

                    //DES Constructor
                    //Roaming_gNB_Experiment gNBr_DES = new Roaming_gNB_Experiment(des);

                    //Hash Constructor
                    //Roaming_gNB_Experiment gNBr_Hash = new Roaming_gNB_Experiment(Hash);

                    //Keccak Constructor
                    //Roaming_gNB_Experiment gNBr_Keccak = new Roaming_gNB_Experiment(Keccak);

                    //RSA Constructor
                    //MigrationModel.Roaming_gNB_Experiment gNBr_RSA = new MigrationModel.Roaming_gNB_Experiment(rsa);

                    //KYBER Constructor
                    //Security.setProperty("crypto.policy", "unlimited");
                    //Security.addProvider(new KyberJCE());
                    //Roaming_gNB_Experiment gNBr_Kyber = new Roaming_gNB_Experiment(kyber);

                    if(Received_instance == Attempt_Limit-2) {

                        for (int x = 2; x < Attempt_Limit-3; x++) {

                            Total_PT = Total_PT + ProcessTime[x];
                            System.out.print(ProcessTime[x] + ", ");
                        }

                        VerticalSpace();

                        System.out.println("Average Process Time [ms]: " + (Total_PT / (Attempt_Limit-3)));

                        VerticalSpace();
                    }

                } finally {
                    socket.close();
                }
            }

        } finally {
            serverSocket.close();

        }



    }


    public Roaming_gNB_Experiment(BigInteger RSA) throws NoSuchAlgorithmException,IOException, InvalidKeySpecException,Exception, NullPointerException {


        KeyFactory kf = KeyFactory.getInstance("RSA");

        InputStream is = this.getClass().getClassLoader().getResourceAsStream("PRIVATE_KEY_FILE.txt");

        String stringPrivateKey = new String(is.readAllBytes());
        is.close();

        System.out.println("Loaded String Private Key : "+stringPrivateKey);

        byte[] decodedPrivateKey = Base64.getDecoder().decode(stringPrivateKey);

        //System.out.println("Decoded Private Key : "+decodedPrivateKey);

        KeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decodedPrivateKey);

        //System.out.println("Key Specification of Private Key : "+keySpecPrivate);

        privateKey = kf.generatePrivate(keySpecPrivate);

        is = this.getClass().getClassLoader().getResourceAsStream("PUBLIC_KEY_FILE.txt");

        String stringPublicKey = new String(is.readAllBytes());
        is.close();

        System.out.println("Loaded String Public Key : "+stringPublicKey);

        byte[] decodedPublicKey = Base64.getDecoder().decode(stringPublicKey);

        KeySpec keySpecPublic = new X509EncodedKeySpec(decodedPublicKey);

        publicKey = kf.generatePublic(keySpecPublic);

        System.out.println("Loaded RSA Private Key : "+privateKey);
        System.out.println("Loaded RSA Public Key : "+publicKey);

        byte[] CipherText = Base64.getDecoder().decode(encryptedString);

        Start_time = System.nanoTime();
        String decryptedString = RSA_decrypt(CipherText,privateKey);
        End_time = System.nanoTime();
        Process_time = TimeDifference(Start_time,End_time);

        System.out.println("RSA Decrypted Text : "+decryptedString);
        System.out.println("Time taken for the Decryption Process [ms]: "+Nano2MilliSeconds(Process_time));

    }

    public Roaming_gNB_Experiment(boolean kyb) throws IOException,NullPointerException{

        Start_time = System.nanoTime();
        System.out.println("Received Message : " + encryptedString + " received at " + getCurrentTimestamp());
        System.out.println("Received Instance : " + Received_instance);


        End_time = System.nanoTime();

        //System.out.println("AES Decrypted Text : " + decryptedString);
        //System.out.println("AES Decrypted Text Length [bytes]: " + decryptedString.length());
        Process_time = TimeDifference(Start_time, End_time)/1000000;
        System.out.println("Time taken for the Decryption Process [ms]: " + Process_time);


        VerticalSpace();
        ProcessTime[Received_instance] = Process_time;
        Received_instance++;

        System.out.println("Total Process Times: ");
        VerticalSpace();


        VerticalSpace();
    }


    public Roaming_gNB_Experiment(int AES) throws IOException,NullPointerException{

            Start_time = System.nanoTime();
            System.out.println("Received Message : " + encryptedString + " received at " + getCurrentTimestamp());
            System.out.println("Received Instance : " + Received_instance);

            String decryptedString = AES_Decrypt(encryptedString);
            End_time = System.nanoTime();

            System.out.println("AES Decrypted Text : " + decryptedString);
            System.out.println("AES Decrypted Text Length [bytes]: " + decryptedString.length());
            Process_time = TimeDifference(Start_time, End_time)/1000000;
            System.out.println("Time taken for the Decryption Process [ms]: " + Process_time);


            VerticalSpace();
            ProcessTime[Received_instance] = Process_time;
            Received_instance++;

        System.out.println("Total Process Times: ");
        VerticalSpace();


        VerticalSpace();
    }

    public Roaming_gNB_Experiment(int AES_STREAM[]) throws IOException,NullPointerException{

        Start_time = System.nanoTime();
        System.out.println("Received Message : " + encryptedString + " received at " + getCurrentTimestamp());
        System.out.println("Received Instance : " + Received_instance);

        String decryptedString = AES_Decrypt_Stream(encryptedString);
        End_time = System.nanoTime();

        System.out.println("AES Decrypted Text : " + decryptedString);
        System.out.println("AES Decrypted Text Length [bytes]: " + decryptedString.length());
        Process_time = TimeDifference(Start_time, End_time)/1000000;
        System.out.println("Time taken for the Decryption Process [ms]: " + Process_time);


        VerticalSpace();
        ProcessTime[Received_instance] = Process_time;
        Received_instance++;

        System.out.println("Total Process Times: ");
        VerticalSpace();


        VerticalSpace();
    }

    public Roaming_gNB_Experiment(double BF) throws IOException,NullPointerException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Start_time = System.nanoTime();
        System.out.println("Received Message : " + encryptedString + " received at " + getCurrentTimestamp());
        System.out.println("Received Instance : " + Received_instance);

        String decryptedString = BF_decrypt(encryptedString,SECRET_KEY_BF);
        End_time = System.nanoTime();

        System.out.println("BlowFish Decrypted Text : " + decryptedString);
        System.out.println("BlowFish Decrypted Text Length [bytes]: " + decryptedString.length());
        Process_time = TimeDifference(Start_time, End_time)/1000000;
        System.out.println("Time taken for the Decryption Process [ms]: " + Process_time);

        VerticalSpace();
        ProcessTime[Received_instance] = Process_time;
        Received_instance++;

        System.out.println("Total Process Times: ");
        VerticalSpace();

        VerticalSpace();
    }

    public Roaming_gNB_Experiment(float DES) throws IOException,NullPointerException{

        Start_time = System.nanoTime();
        System.out.println("Received Message : " + encryptedString + " received at " + getCurrentTimestamp());
        System.out.println("Received Instance : " + Received_instance);

        String decryptedString = DES_Decrypt(encryptedString);
        End_time = System.nanoTime();
        Process_time = TimeDifference(Start_time,End_time)/1000000;
        System.out.println("DES Decrypted Text : "+decryptedString);
        System.out.println("DES Decrypted Text Length [bytes]: " + decryptedString.length());
        System.out.println("Time taken for the Decryption Process [ms]: "+Nano2MilliSeconds(Process_time));

        VerticalSpace();
        ProcessTime[Received_instance] = Process_time;
        Received_instance++;

        System.out.println("Total Process Times: ");
        VerticalSpace();


        VerticalSpace();

    }

    public Roaming_gNB_Experiment(long hash) throws IOException,NullPointerException {

        Start_time = System.nanoTime();
        System.out.println("Received Message : " + encryptedString + " received at " + getCurrentTimestamp());
        System.out.println("Received Instance : " + Received_instance);

        Received_instance++;

        VerticalSpace();


    }

    public Roaming_gNB_Experiment(char Kecc) throws IOException,NullPointerException {

        Start_time = System.nanoTime();
        System.out.println("Received Message : " + encryptedString + " received at " + getCurrentTimestamp());
        System.out.println("Received Instance : " + Received_instance);

        Received_instance++;

        VerticalSpace();


    }

    public static void main(String[] args) throws UnknownHostException, Exception {

        Security.addProvider(new BouncyCastleProvider());

        System.out.println("Roaming gNB is Functioning at..\n"+getCurrentTimestamp()+"\n\n");

        //Socket Constructor
        Roaming_gNB_Experiment gNBr = new Roaming_gNB_Experiment();


    }

    public static String RandomStringGenerator() {
        int leftLimit = 97; // letter 'a'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = PlaintextLength;
        Random random = new Random();

        String generatedString = random.ints(leftLimit, rightLimit + 1)
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        return generatedString;
    }

    public static Timestamp getCurrentTimestamp(){
        return new Timestamp(System.currentTimeMillis());
    }

    public static Timestamp getCurrentTS(){
        return new Timestamp(System.nanoTime());
    }

    public static long Nano2MilliSeconds(long nanoTime){

        return (nanoTime/1000000);

    }

    public void VerticalSpace(){

        System.out.println("\n\n");
    }

    public static long TimeDifference(long start_time, long end_time){

        return (end_time - start_time);
    }

    public static String Hash (String message) throws NoSuchAlgorithmException {
        // getInstance() method is called with algorithm SHA-512
        MessageDigest md = MessageDigest.getInstance("SHA-512");

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

    /////////////////////////// RSA /////////////////////////////////////////////
    public static byte[] RSA_encrypt (String plainText,PublicKey publicKey ) throws Exception
    {
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //Perform Encryption
        byte[] cipherText = cipher.doFinal(plainText.getBytes()) ;

        return cipherText;
    }

    public static String RSA_decrypt (byte[] cipherTextArray, PrivateKey privateKey) throws Exception
    {
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        //Initializing the Cipher only with the RSA without any padding or a BLock Cipher Mode
        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        //Perform Decryption
        byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);

        return new String(decryptedTextArray);
    }

    ///////////////////////////////////// AES /////////////////////////////////////////
    public static String AES_Encrypt(String strToEncrypt) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, AES_Key_Length);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

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
            //Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            //cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static String AES_Decrypt_Stream(String strToDecrypt) {
        try {

            //Wrap the data into a byte buffer to ease the reading process
            ByteBuffer byteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(strToDecrypt));

            int noonceSize = byteBuffer.getInt();

            /*
            //Make sure that the file was encrypted properly
            if(noonceSize < 12 || noonceSize >= 16) {
                throw new IllegalArgumentException("Nonce size is incorrect. Make sure that the incoming data is an AES encrypted file.");
            }
            */

            byte[] iv = new byte[noonceSize];
            byteBuffer.get(iv);

            //Prepare your key/password
            SecretKey secretKey = generateSecretKey(SECRET_KEY, iv);

            //get the rest of encrypted data
            byte[] cipherBytes = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherBytes);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);

            //Encryption mode on!
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            //Encrypt the data
            //return cipher.doFinal(cipherBytes);

            return new String(cipher.doFinal(cipherBytes));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static SecretKey generateSecretKey(String password, byte [] iv) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), iv, 65536, 128); // AES-128
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] key = secretKeyFactory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }

    public static byte[] AES_Decrypt_ByteArray(byte[] bytesToDecrypt) {
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
            return cipher.doFinal(bytesToDecrypt);
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    /////////////////////////////////////////////////  DES  //////////////////////////////////////////////////////////////

    public static String DES_Encrypt(String str) {
        try {
            byte[] keyBytes = SECRET_KEY_DES.getBytes();
            byte[] content = str.getBytes();
            DESKeySpec keySpec = new DESKeySpec(keyBytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            SecretKey key = keyFactory.generateSecret(keySpec);

            Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(keySpec.getKey()));
            byte[] result = cipher.doFinal(content);
            return byteToHexString(result);
        } catch (Exception e) {
            System.out.println("exception:" + e.toString());
        }
        return null;
    }

    public static String DES_Decrypt(String str) {
        try {
            byte[] keyBytes = SECRET_KEY_DES.getBytes();
            byte[] content = hexToByteArray(str);
            DESKeySpec keySpec = new DESKeySpec(keyBytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            SecretKey key = keyFactory.generateSecret(keySpec);

            Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(keyBytes));
            byte[] result = cipher.doFinal(content);
            return new String(result);
        } catch (Exception e) {
            System.out.println("exception:" + e.toString());
        }
        return null;
    }

    private static String byteToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length);
        String sTemp;
        for (byte aByte : bytes) {
            sTemp = Integer.toHexString(0xFF & aByte);
            if (sTemp.length() < 2)
                sb.append(0);
            sb.append(sTemp.toUpperCase());
        }
        return sb.toString();
    }

    private static byte[] hexToByteArray(String inHex) {
        int hexLen = inHex.length();
        byte[] result;
        if (hexLen % 2 == 1) {
            hexLen++;
            result = new byte[(hexLen / 2)];
            inHex = "0" + inHex;
        } else {
            result = new byte[(hexLen / 2)];
        }
        int j = 0;
        for (int i = 0; i < hexLen; i += 2) {
            result[j] = (byte) Integer.parseInt(inHex.substring(i, i + 2), 16);
            j++;
        }
        return result;
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

    /////////////////////       FILE MIGRATION      //////////////////////////////////
    public static void receiveFile(String path, DataInputStream dataInputStream) throws Exception{
        int bytes = 0;
        FileOutputStream fileOutputStream = new FileOutputStream(path);

        long size = dataInputStream.readLong();     // read file size
        byte[] buffer = new byte[4*1024];


        while (size > 0 && (bytes = dataInputStream.read(buffer, 0, (int)Math.min(buffer.length, size))) != -1) {
            fileOutputStream.write(buffer,0,bytes);
            size -= bytes;      // read upto file size
        }
        fileOutputStream.close();

    }

    public static void receiveEncryptedFile(String path, String filename, DataInputStream dataInputStream) throws Exception{
        int bytes = 0;
        FileOutputStream fileOutputStream1 = new FileOutputStream(path+"/EncryptedFile.iso");

        long size = dataInputStream.readLong();     // read file size
        byte[] buffer = new byte[4*1024];


        while (size > 0 && (bytes = dataInputStream.read(buffer, 0, (int)Math.min(buffer.length, size))) != -1) {
            fileOutputStream1.write(buffer,0,bytes);
            size -= bytes;      // read upto file size
        }
        fileOutputStream1.close();

        File Encryptedfile = new File(path+"/EncryptedFile.iso");

        //byte[] fileContent = Files.readAllBytes(file);

        FileInputStream fileInputStream1 = new FileInputStream(Encryptedfile);
        byte[] content = new byte[(int)Encryptedfile.length()];

        fileInputStream1.read(content);

        byte[] DecryptedArray = AES_Decrypt_ByteArray(content);

        try (FileOutputStream fileOutputStream = new FileOutputStream(path+"/"+filename)) {
            fileOutputStream.write(DecryptedArray);
        }

        fileInputStream1.close();

    }

}
