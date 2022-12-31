package MigrationModel;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
//import org.apache.commons.codec.binary.Base64;
import MigrationModel.*;
//import com.swiftcryptollc.crypto.provider.*;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Source_gNB_Experiment {

    public static String Plaintext;
    public static int PlaintextLength = 10; //bytes
    public static int RSA_Key_length = 4096; //bits
    public static int AES_Key_Length = 256; //bits
    public static int AES_SALT_Length = 8; //bytes
    public static String HASH_ALGO = "SHA-512";
    public static int Keccak_Key_Length = 512;

    public static double rc4[];
    public static int aes;
    public static int aes_stream[];
    public static float des;
    public static BigInteger rsa;
    public static long hash;
    public double BF;
    public static char Keccak;
    public static boolean kyber;

    public static int PORT = 9000;

    public static long Start_time;
    public static long End_time;
    public static Long Process_time;
    public static long Process_time2;
    public static long Received_time;
    public static long Sending_time;
    public static long File_Send_Start_time;
    public static long File_Send_End_time;
    public static long File_Receive_Start_time;
    public static long File_Receive_End_time;
    public static Long Process_time_Send;
    public static Long Process_time_Receive;

    public static String encryptedString;


    //Secret Key for BlowFish
    public static final String SECRET_KEY_BF = "5oquil2oo2vb63e8ionujny65oquil2oo2vb63e8ionujny6";

    //Secret Key for DES
    public static final String SECRET_KEY_DES = "5oquil2oo2vb63e8ionujny6";

    //Secret Key and Salt for the AESEncrypt() and AESDecrypt() Functions
    public static final String SECRET_KEY = "my_super_secret_key_ho_ho_ho";
    public static final String SALT = "ssshhhhhhhhhhh!!!!ssshhhhhhhhhhh!!!!";

    public static int Attempt_Limit = 102;

    public static Long ProcessTime[];
    public static Long DecryptionTime[];
    public static Long Total_PT;
    public static Long Total_DT;
    public static int DigestSize[];
    public static boolean exit = false;
    public static int Attempt = 0;

    private static final String ENCRYPTION_ALGORITHM = "ARCFOUR"; // or "RC4"

    public static DataOutputStream dataOutputStream = null;
    public static DataInputStream dataInputStream = null;


    public Source_gNB_Experiment(String[] args) throws IOException, NoSuchAlgorithmException, NullPointerException, Exception {

        InetAddress ipAddress = InetAddress.getLocalHost();

        ProcessTime =  new Long[Attempt_Limit];
        //DecryptionTime =  new Long[Attempt_Limit];
        Total_PT = new Long("0");
        //Total_DT = new Long("0");
        DigestSize = new int[Attempt_Limit];


            //////////////////////////      SECURITY EXPERIMENTS        ////////////////////////////////////////


            while(exit == false) {

                Socket socket = new Socket(ipAddress, PORT);


                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);


                //%%%%%%%%%%%%%%%%%%%%%% AES ENCRYPTION %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
                    //RC4 Constructor
                    //Source_gNB_Experiment gNBs_RC4 = new Source_gNB_Experiment(rc4);


                //%%%%%%%%%%%%%%%%%%%%%% AES ENCRYPTION %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                //AES Constructor
                Source_gNB_Experiment gNBs_AES = new Source_gNB_Experiment(aes);

                //%%%%%%%%%%%%%%%%%%%%%% AES ENCRYPTION %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                    // AES Constructor
                  //  Source_gNB_Experiment gNBs_AES_stream = new Source_gNB_Experiment(aes_stream);

                //%%%%%%%%%%%%%%%%%%%%%% BF ENCRYPTION %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                //BlowFish Constructor
                //Source_gNB_Experiment gNBs_BF = new Source_gNB_Experiment(BF);

                //%%%%%%%%%%%%%%%%%%%%%% DES ENCRYPTION %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                //DES Constructor
                //Source_gNB_Experiment gNBs_DES = new Source_gNB_Experiment(des);

                //%%%%%%%%%%%%%%%%%%%%%% HASHING %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                //Hash Constructor
                //Source_gNB_Experiment gNBs_Hash = new Source_gNB_Experiment(hash);

                //%%%%%%%%%%%%%%%%%%%%%% KECCAK HASHING %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                //Keccak Constructor
                //Security.addProvider(new BouncyCastleProvider());
                //Source_gNB_Experiment gNBs_Keccak = new Source_gNB_Experiment(Keccak);

                //%%%%%%%%%%%%%%%%%%%%%% KYBER ENCRYPTION %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                //KYBER Constructor
                //Security.setProperty("crypto.policy", "unlimited");
                //Security.addProvider(new KyberJCE());
                //Source_gNB_Experiment gNBs_Kyber = new Source_gNB_Experiment(kyber);


                //%%%%%%%%%%%%%%%%%%%%%% RSA ENCRYPTION %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                //RSA Constructor
                //MigrationModel.Source_gNB_Experiment gNBs_RSA = new MigrationModel.Source_gNB_Experiment(rsa);


                //%%%%%%%%%%%%%%%%%%%%%%  MESSAGE SENDING  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


                out.println(encryptedString);

                Sending_time = System.nanoTime();

                System.out.println("Message Sent time [ns]: " + Sending_time);

                Process_time = TimeDifference(Start_time,End_time);

                System.out.println("Time taken for the Encryption Process [ms]: "+Nano2MilliSeconds(Process_time));

                VerticalSpace();

                Attempt++;

                if(Attempt == Attempt_Limit){
                    exit = true;
                }


            }

            System.out.println("Total Process Times: ");
            VerticalSpace();
            for(int x=2; x < Attempt_Limit; x++){

                Total_PT = Total_PT + ProcessTime[x];
                System.out.print(ProcessTime[x]+", ");
            }

        //for(int x=2; x < Attempt_Limit; x++){

            //Total_DT = Total_DT + DecryptionTime[x];
            //System.out.print(ProcessTime[x]+", ");
        //}

        VerticalSpace();
        System.out.println("Average Process Time [ms]: " + (Total_PT/(Attempt_Limit-2)));
        //System.out.println("Average Decryption Time : "+(Total_DT/(Attempt_Limit-2)));

        //System.out.println("Average Digest Size [bytes]: " + Arrays.stream(DigestSize).average());
        //System.out.println("Minimum Digest Size [bytes]: " + Arrays.stream(DigestSize).min());
        //System.out.println("Maximum Digest Size [bytes]: " + Arrays.stream(DigestSize).max());

        VerticalSpace();


    }
/*
    public Source_gNB_Experiment(double rc4[]) throws IOException, NoSuchAlgorithmException, NullPointerException,NoSuchPaddingException,InvalidKeySpecException, InvalidKeyException,BadPaddingException,IllegalBlockSizeException,InvalidAlgorithmParameterException{



        String plaintext = "Howdy!";

        KeyGenerator rc4KeyGenerator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
        SecretKey secretKey = rc4KeyGenerator.generateKey();
        Cipher RC4 = Cipher.getInstance(ENCRYPTION_ALGORITHM);

        byte[] ciphertextBytes = encrypt_RC4(plaintext, secretKey, RC4);

        decrypt_RC4(secretKey, RC4, ciphertextBytes);

    }

*/
    public Source_gNB_Experiment(int AES) throws IOException, NoSuchAlgorithmException, NullPointerException {

        System.out.println("Attempt : " + Attempt);

        //Random String with Different Byte Sizes
        Plaintext = RandomStringGenerator();
        System.out.println("Plaintext : "+Plaintext);
        System.out.println("Size of the Plaintext : "+Plaintext.getBytes().length);

        Start_time = System.nanoTime();
        encryptedString = AES_Encrypt(Plaintext);
        End_time = System.nanoTime();
        System.out.println("AES Encrypted String : " + encryptedString);
        System.out.println("Size of the Encrypted String [bytes]: " + encryptedString.getBytes().length);
        System.out.println("Size of the Key [bytes]: " + SALT.getBytes().length);

        Process_time = TimeDifference(Start_time, End_time)/1000000;

        System.out.println("Time taken for the Encryption Process [ms]: " + Process_time);

        ProcessTime[Attempt] = Process_time;

        VerticalSpace();

    }

    public Source_gNB_Experiment(int AES_STREAM[]) throws IOException, NoSuchAlgorithmException, NullPointerException {

        System.out.println("Attempt : " + Attempt);

        //Random String with Different Byte Sizes
        Plaintext = RandomStringGenerator();
        System.out.println("Plaintext : "+Plaintext);
        System.out.println("Size of the Plaintext : "+Plaintext.getBytes().length);

        Start_time = System.nanoTime();
        encryptedString = AES_Encrypt_Stream(Plaintext);
        End_time = System.nanoTime();
        System.out.println("AES Encrypted String : " + encryptedString);
        System.out.println("Size of the Encrypted String [bytes]: " + encryptedString.getBytes().length);
        System.out.println("Size of the Key [bytes]: " + SALT.getBytes().length);

        Process_time = TimeDifference(Start_time, End_time)/1000000;

        System.out.println("Time taken for the Encryption Process [ms]: " + Process_time);

        ProcessTime[Attempt] = Process_time;

        VerticalSpace();

    }

    /*
    public Source_gNB_Experiment(boolean kyb) throws IOException, NoSuchAlgorithmException, NullPointerException {

        System.out.println("Attempt : " + Attempt);

        //Random String with Different Byte Sizes
        Plaintext = RandomStringGenerator();
        System.out.println("Plaintext : "+Plaintext);
        System.out.println("Size of the Plaintext : "+Plaintext.getBytes().length);

        Start_time = System.nanoTime();

        KeyPairGenerator keyGen = null;
        try {
            Kyber1024KeyPairGenerator keyGen1024 = new Kyber1024KeyPairGenerator();
            //Kyber768KeyPairGenerator keyGen768 = new Kyber768KeyPairGenerator();
            //Kyber512KeyPairGenerator keyGen512 = new Kyber512KeyPairGenerator();
            KeyPair keyPair = keyGen1024.generateKeyPair();
            //KeyPair keyPair = keyGen768.generateKeyPair();
            //KeyPair keyPair = keyGen512.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            KyberKeyAgreement keyAgreement = new KyberKeyAgreement();
            keyAgreement.engineInit(privateKey);

            KyberEncrypted encrypted = keyAgreement.encrypt1024(Plaintext.getBytes(), publicKey.getEncoded());
            //KyberEncrypted encrypted = keyAgreement.encrypt768(Plaintext.getBytes(), publicKey.getEncoded());
            //KyberEncrypted encrypted = keyAgreement.encrypt512(Plaintext.getBytes(), publicKey.getEncoded());
            encryptedString = encrypted.toString();

            End_time = System.nanoTime();
            System.out.println("Kyber Encrypted String : " + encryptedString);
            System.out.println("Size of the Encrypted String [bytes]: " + encryptedString.getBytes().length);

            Process_time = TimeDifference(Start_time, End_time)/1000000;

            System.out.println("Time taken for the Encryption Process [ms]: " + Process_time);

            ProcessTime[Attempt] = Process_time;

            DigestSize[Attempt] = encryptedString.getBytes().length;


//            KyberDecrypted decrypted = keyAgreement.decrypt1024(encrypted.getCipherText());
            Start_time = System.nanoTime();
            KyberDecrypted kyberDecrypted = keyAgreement.decrypt(KyberKeySize.KEY_1024, new KyberCipherText(encrypted.getCipherText().getC(), null, null));
            //KyberDecrypted kyberDecrypted = keyAgreement.decrypt(KyberKeySize.KEY_768, new KyberCipherText(encrypted.getCipherText().getC(), null, null));
            //KyberDecrypted kyberDecrypted = keyAgreement.decrypt(KyberKeySize.KEY_512, new KyberCipherText(encrypted.getCipherText().getC(), null, null));
            String reconstructedText =  new String(kyberDecrypted.getVariant().getBytes());
            End_time = System.nanoTime();
            System.out.println("Decrypted Text : "+reconstructedText);
            DecryptionTime[Attempt] = TimeDifference(Start_time, End_time)/1000000;

            System.out.println("Time taken for the Decryption Process [ms]: " + DecryptionTime[Attempt]);

        } catch (Exception e) {
            e.printStackTrace();
        }


        //System.out.println("Size of the Key [bytes]: " + SALT.getBytes().length);





        VerticalSpace();

    }
    */

    public Source_gNB_Experiment(double BF) throws IOException, NoSuchAlgorithmException, NullPointerException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        System.out.println("Attempt : " + Attempt);

        //Random String with Different Byte Sizes
        Plaintext = RandomStringGenerator();
        System.out.println("Plaintext : "+Plaintext);
        System.out.println("Size of the Plaintext : "+Plaintext.getBytes().length);

        Start_time = System.nanoTime();
        //encryptedString = BF_encrypt(Plaintext, SECRET_KEY_BF);
        encryptedString = BF_encrypt(Plaintext, SECRET_KEY_BF);
        End_time = System.nanoTime();
        System.out.println("BlowFish Encrypted String : " + encryptedString);
        System.out.println("Size of the Encrypted String [bytes]: " + encryptedString.getBytes().length);
        System.out.println("Size of the Key [bytes]: " + SECRET_KEY_BF.getBytes().length);

        Process_time = TimeDifference(Start_time, End_time)/1000000;

        System.out.println("Time taken for the Encryption Process [ms]: " + Process_time);

        ProcessTime[Attempt] = Process_time;

        VerticalSpace();

    }

    public Source_gNB_Experiment(long hash) throws IOException, NoSuchAlgorithmException, NullPointerException {

        System.out.println("Attempt : " + Attempt);

        //Random String with Different Byte Sizes
        Plaintext = RandomStringGenerator();
        System.out.println("Plaintext : "+Plaintext);
        System.out.println("Size of the Plaintext : "+Plaintext.getBytes().length);

        Start_time = System.nanoTime();
        encryptedString = Hash(Plaintext);
        End_time = System.nanoTime();
        System.out.println("Hashed String : " + encryptedString);
        System.out.println("Size of the Digest [bytes]: " + encryptedString.getBytes().length);
        System.out.println("Size of the SALT [bytes]: " + SALT.getBytes().length);

        Process_time = TimeDifference(Start_time, End_time)/1000000;

        System.out.println("Time taken for the Encryption Process [ms]: " + Process_time);

        ProcessTime[Attempt] = Process_time;

        VerticalSpace();

    }

    public Source_gNB_Experiment(char kecc) throws IOException, NoSuchAlgorithmException, NullPointerException {

        System.out.println("Attempt : " + Attempt);

        //Random String with Different Byte Sizes
        Plaintext = RandomStringGenerator();
        System.out.println("Plaintext : "+Plaintext);
        System.out.println("Size of the Plaintext : "+Plaintext.getBytes().length);

        Start_time = System.nanoTime();
        encryptedString = hashKeccak(Plaintext);
        End_time = System.nanoTime();
        System.out.println("Keccak Hashed String : " + encryptedString);
        System.out.println("Size of the Digest [bytes]: " + encryptedString.getBytes().length);
        System.out.println("Size of the SALT [bytes]: " + SALT.getBytes().length);

        DigestSize[Attempt] = encryptedString.getBytes().length;

        Process_time = TimeDifference(Start_time, End_time)/1000000;

        System.out.println("Time taken for the Encryption Process [ms]: " + Process_time);

        ProcessTime[Attempt] = Process_time;

        VerticalSpace();

    }

    public Source_gNB_Experiment(float DES) throws IOException, NoSuchAlgorithmException, NullPointerException {

        System.out.println("Attempt : " + Attempt);

        //Random String with Different Byte Sizes
        Plaintext = RandomStringGenerator();
        System.out.println("Plaintext : "+Plaintext);
        System.out.println("Size of the Plaintext : "+Plaintext.getBytes().length);

        Start_time = System.nanoTime();
        encryptedString = DES_Encrypt(Plaintext);
        End_time = System.nanoTime();

        System.out.println("DES Encrypted String : "+encryptedString);
        System.out.println("Size of the Encrypted String [bytes]: " + encryptedString.getBytes().length);

        Process_time = TimeDifference(Start_time,End_time)/1000000;

        System.out.println("Time taken for the Encryption Process [ms]: "+Nano2MilliSeconds(Process_time));

        VerticalSpace();

    }

    public Source_gNB_Experiment(BigInteger RSA) throws IOException, NoSuchAlgorithmException, NullPointerException,Exception {


        // Get an instance of the RSA key generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(RSA_Key_length);

        // Generate the KeyPair
        KeyPair keyPair = keyPairGenerator.generateKeyPair();



        // Get the public and private key
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("RSA Private Key : "+privateKey);
        System.out.println("RSA Public Key : "+publicKey);

        //Creating the Files for storing the Private and Public Keys

        File privateKeyFile = new File("E:/OneDrive/PhD Ireland/PhD Work/MEC/Research Directions/Service Migration Prediction/Implementation/MECMigrationProtocol/out/production/MECMigrationProtocol/PRIVATE_KEY_FILE.txt");
        privateKeyFile.createNewFile();

        File publicKeyFile = new File("E:/OneDrive/PhD Ireland/PhD Work/MEC/Research Directions/Service Migration Prediction/Implementation/MECMigrationProtocol/out/production/MECMigrationProtocol/PUBLIC_KEY_FILE.txt");
        publicKeyFile.createNewFile();

        byte[] encodedPublicKey = publicKey.getEncoded();
        String b64PublicKey = Base64.getEncoder().encodeToString(encodedPublicKey);

        byte[] encodedPrivateKey = privateKey.getEncoded();
        String b64PrivateKey = Base64.getEncoder().encodeToString(encodedPrivateKey);

        //Writing the Keys to the created files
        try (OutputStreamWriter publicKeyWriter =
                     new OutputStreamWriter(
                             new FileOutputStream(publicKeyFile),
                             StandardCharsets.US_ASCII.newEncoder())) {
            publicKeyWriter.write(b64PublicKey);
        }

        try (OutputStreamWriter privateKeyWriter =
                     new OutputStreamWriter(
                             new FileOutputStream(privateKeyFile),
                             StandardCharsets.US_ASCII.newEncoder())) {
            privateKeyWriter.write(b64PrivateKey);
        }

        System.out.println("Keys are written to the Files.......\n\n");

        VerticalSpace();

        //Encryption
        Start_time = System.nanoTime();
        long TS1 = System.currentTimeMillis();
        byte[] cipherTextArray = RSA_encrypt(Plaintext, publicKey);
        encryptedString = Base64.getEncoder().encodeToString(cipherTextArray);
        End_time = System.nanoTime();
        long TS2 = System.currentTimeMillis();
        Process_time = TimeDifference(Start_time,End_time);
        Process_time2 = TimeDifference(TS1,TS2);

        System.out.println("RSA Encrypted String : "+encryptedString);
        System.out.println("Size of the Encrypted String : "+encryptedString.getBytes().length);
        System.out.println("Time taken for the Encryption Process [ms]: "+Nano2MilliSeconds(Process_time));
        System.out.println("Time taken for the Encryption Process in Milli [ms]: "+Process_time2);

        byte[] cipherText = Base64.getDecoder().decode(encryptedString);

        String plainText = RSA_decrypt(cipherText, privateKey);

        System.out.println("RSA Decrypted String : "+plainText);
        System.out.println("Size of the Decrypted String : "+plainText.getBytes().length);



    }

    public static void main(String[] args) throws UnknownHostException, Exception {

        System.out.println("Source gNB MEC Server is Running at "+getCurrentTimestamp());


        //System.out.println();
        //Socket Constructor
        Source_gNB_Experiment gNBs = new Source_gNB_Experiment(args);

        //AES Constructor
        //MigrationModel.Source_gNB_Experiment gNBs_AES = new MigrationModel.Source_gNB_Experiment(aes);

        //RSA Constructor
        //MigrationModel.Source_gNB_Experiment gNBs_RSA = new MigrationModel.Source_gNB_Experiment(rsa);

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

    /////////////////////////// RSA /////////////////////////////////////////////
    public static byte[] RSA_encrypt (String plainText,PublicKey publicKey ) throws Exception
    {
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");


        //Initializing the Cipher only with the RSA without any padding or a BLock Cipher Mode
        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

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
            //Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            //cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder()
                    .encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String AES_Encrypt_Stream(String strToEncrypt) {
        try {
            //Prepare the nonce
            SecureRandom secureRandom = new SecureRandom();

            //Noonce should be 12 bytes
            byte[] iv = new byte[12];
            secureRandom.nextBytes(iv);

            //Prepare your key/password
            SecretKey secretKey = generateSecretKey(SECRET_KEY, iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);

            //Encryption mode on!
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            //Encrypt the data
            byte [] encryptedData = cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder()
                    .encodeToString(encryptedData);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static SecretKey generateSecretKey(String password, byte [] iv) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), iv, 65536, 128); // AES-128
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] key = secretKeyFactory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }

    public static byte[] AES_Encrypt_ByteArray(byte[] byteToEncrypt) {
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
            return cipher.doFinal(byteToEncrypt);
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

    ////////////////////////////////////////////////    RC4     ////////////////////////////////////////////////////////
/*
    private static byte[] encrypt_RC4(String plaintext, SecretKey secretKey, Cipher rc4) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        rc4.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] ciphertextBytes = rc4.doFinal(plaintextBytes);
        System.out.println("RC4 ciphertext base64 encoded: " + Base64.encodeBase64String(ciphertextBytes));
        return ciphertextBytes;
    }

    private static void decrypt_RC4(SecretKey secretKey, Cipher rc4, byte[] ciphertextBytes) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        rc4.init(Cipher.DECRYPT_MODE, secretKey, rc4.getParameters());
        byte[] byteDecryptedText = rc4.doFinal(ciphertextBytes);
        String plaintextBack = new String(byteDecryptedText);
        System.out.println("Decrypted back to: " + plaintextBack);
    }
*/

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

    //////////////////////      BOUNCY CASTLE       ////////////////////////////////
    public static String hashKeccak(String data) {
        byte[] dataBytes = data.getBytes();
        Keccak.DigestKeccak md = new Keccak.DigestKeccak(Keccak_Key_Length);
        md.reset();
        md.update(dataBytes, 0, dataBytes.length);
        byte[] hashedBytes = md.digest();
        return new String(hashedBytes);
    }


    //////////////////////////      File Migration      ///////////////////////////////////

    public static void MigrateFile(String path, DataOutputStream dataOutputStream) throws Exception{
        int bytes = 0;
        File file = new File(path);
        FileInputStream fileInputStream = new FileInputStream(file);

        // send file size
        dataOutputStream.writeLong(file.length());
        // break file into chunks
        byte[] buffer = new byte[4*1024];
        while ((bytes=fileInputStream.read(buffer))!=-1){
            dataOutputStream.write(buffer,0,bytes);
            dataOutputStream.flush();
        }
        fileInputStream.close();
    }

    public static void MigrateEncryptedFile(String path, String filename, DataOutputStream dataOutputStream) throws Exception{
        int bytes = 0;
        File file = new File(path+"/"+filename);

        //byte[] fileContent = Files.readAllBytes(file);

        FileInputStream fileInputStream1 = new FileInputStream(file);
        byte[] content = new byte[(int)file.length()];

        fileInputStream1.read(content);

        byte[] EncryptedArray = AES_Encrypt_ByteArray(content);

        try (FileOutputStream fileOutputStream = new FileOutputStream(path+"/EncryptedImage.iso")) {
            fileOutputStream.write(EncryptedArray);
        }

        fileInputStream1.close();

        File Encryptedfile = new File(path+"/EncryptedImage.iso");
        FileInputStream fileInputStream2 = new FileInputStream(Encryptedfile);

        //Files.write(Encryptedfile,EncryptedArray);

        // send file size
        dataOutputStream.writeLong(Encryptedfile.length());
        // break file into chunks
        byte[] buffer = new byte[4*1024];
        while ((bytes=fileInputStream2.read(buffer))!=-1){
            dataOutputStream.write(buffer,0,bytes);
            dataOutputStream.flush();
        }
        fileInputStream2.close();
    }

}