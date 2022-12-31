package MigrationModel;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
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
import java.security.spec.KeySpec;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import MigrationModel.*;
//import com.swiftcryptollc.crypto.provider.*;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Source_gNB_Migration {

    public static String Plaintext;
    public static int PlaintextLength = 1000000; //bytes
    public static int RSA_Key_length = 4096; //bits
    public static int AES_Key_Length = 256; //bits
    public static int AES_SALT_Length = 8; //bytes
    public static String HASH_ALGO = "SHA-512";
    public static int Keccak_Key_Length = 512;

    public static int aes;
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


    public static DataOutputStream dataOutputStream = null;
    public static DataInputStream dataInputStream = null;


    public Source_gNB_Migration(String[] args) throws IOException, NoSuchAlgorithmException, NullPointerException, Exception {

        ProcessTime =  new Long[Attempt_Limit];
        //DecryptionTime =  new Long[Attempt_Limit];
        Total_PT = new Long("0");
        //Total_DT = new Long("0");
        DigestSize = new int[Attempt_Limit];

        InetAddress ipAddress = InetAddress.getLocalHost();
        //Socket Connection Establishment

        Socket socket = new Socket(ipAddress, PORT);

        //////////////////////////      FILE MIGRATION      ////////////////////////////////////////////

        //MigrationTransfer MT = new MigrationTransfer();
        MigrationTransfer_L2 MT = new MigrationTransfer_L2();


        MT.Migration(socket, SECRET_KEY, AES_Key_Length, "E:/gNBs/", "tpot_arm64.iso");

        File_Send_Start_time = MT.File_Send_Start_time;
        File_Send_End_time = MT.File_Send_End_time;

        System.out.println("File Send Start Time : "+File_Send_Start_time);
        System.out.println("File Send End Time : "+File_Send_End_time);


    }




    public static void main(String[] args) throws UnknownHostException, Exception {

        System.out.println("Source gNB MEC Server is Running at "+getCurrentTimestamp());


        //System.out.println();
        //Socket Constructor
        Source_gNB_Migration gNBs = new Source_gNB_Migration(args);

        //AES Constructor
        //MigrationModel.Source_gNB_Migration gNBs_AES = new MigrationModel.Source_gNB_Migration(aes);

        //RSA Constructor
        //MigrationModel.Source_gNB_Migration gNBs_RSA = new MigrationModel.Source_gNB_Migration(rsa);

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



}