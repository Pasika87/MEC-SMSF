package MigrationModel;

//import com.swiftcryptollc.crypto.provider.KyberJCE;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
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

import static MigrationModel.Source_gNB_Migration.Attempt;


public class Roaming_gNB_Migration {


    public static String Plaintext;
    public static String encryptedString;
    public static int PlaintextLength = 4; //bytes
    public static int RSA_Key_length = 4096;
    public static int AES_Key_Length = 256;

    public static int aes;
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

    public static int Attempt_Limit = 103;

    public static int Received_instance = 0;
    public static Long[] ProcessTime;
    public static Long Total_PT;

    public static DataOutputStream dataOutputStream = null;
    public static DataInputStream dataInputStream = null;


    public Roaming_gNB_Migration()throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, Exception{

        ProcessTime =  new Long[Attempt_Limit];
        Total_PT = new Long("0");

        ServerSocket serverSocket = new ServerSocket(PORT);

        System.out.println("Roaming gNB Running..................");

        /////////////////////////////////////////       MIGRATION RECEIVING     //////////////////////////////////////////

        //MigrationTransfer MT = new MigrationTransfer();
        MigrationTransfer_L2 MT = new MigrationTransfer_L2();


        MT.Receiving(serverSocket, SECRET_KEY,AES_Key_Length,"F:/gNBr/","tpot_arm64.iso");

        File_Receive_Start_time = MT.File_Receive_Start_time;
        File_Receive_End_time = MT.File_Receive_End_time;

        System.out.println("File Receive Start Time : "+File_Receive_Start_time);
        System.out.println("File Receive End Time : "+File_Receive_End_time);

    }



    public static void main(String[] args) throws UnknownHostException, Exception {

        Security.addProvider(new BouncyCastleProvider());

        System.out.println("Roaming gNB is Functioning at..\n"+getCurrentTimestamp()+"\n\n");

        //Socket Constructor
        Roaming_gNB_Migration gNBr = new Roaming_gNB_Migration();


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
