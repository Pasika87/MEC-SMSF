package MigrationModel;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.encoders.Base32Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLOutput;
import java.util.Random;

import static MigrationModel.MigrationTransfer.TimeDifference;


public class SecurityAlgorithmCostComputation {


    public static long PlaintextLength = 230*1024*1024;

    public static int Runs = 10;

    public static String SECRET_KEY_RC4 = "ThisIsTheRC4SecretKey";

    public static long EncryptionTime[][];
    public static long DecryptionTime[][];
    public static long theta[][];

    public static long AverageEncryptionTime[];
    public static long AverageDecryptionTime[];
    public static long Averagetheta[];

    public static void main(String[] args) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {

        EncryptionTime = new long[100][100];
        DecryptionTime = new long[100][100];
        theta = new long[100][100];

        AverageEncryptionTime = new long[100];
        AverageDecryptionTime = new long[100];
        Averagetheta = new long[100];

        int x = 0;

        while(x < (Runs+2)){

            System.out.println("Run : "+x);

            CostCalculation(x);

            x++;

        }

        //Computing Average Encryption Time
        //AES-128
        long total = 0;
        for (int i=2; i < (Runs+2); i++){

            total = total + EncryptionTime[0][i];

        }
        AverageEncryptionTime[0] = total/Runs;

        //AES-192
        total = 0;
        for (int i=2; i < (Runs+2); i++){

            total = total + EncryptionTime[1][i];

        }
        AverageEncryptionTime[1] = total/Runs;

        //AES-256
        total = 0;
        for (int i=2; i < (Runs+2); i++){

            total = total + EncryptionTime[2][i];

        }
        AverageEncryptionTime[2] = total/Runs;

        //RC4
        total = 0;
        for (int i=2; i < (Runs+2); i++){

            total = total + EncryptionTime[3][i];

        }
        AverageEncryptionTime[3] = total/Runs;

        //BF
        total = 0;
        for (int i=2; i < (Runs+2); i++){

            total = total + EncryptionTime[4][i];

        }
        AverageEncryptionTime[4] = total/Runs;



        //Computing Average Decryption Time
        //AES-128
        total = 0;
        for (int i=2; i < (Runs+2); i++){

            total = total + DecryptionTime[0][i];

        }
        AverageDecryptionTime[0] = total/Runs;

        //AES-192
        total = 0;
        for (int i=2; i < (Runs+2); i++){

            total = total + DecryptionTime[1][i];

        }
        AverageDecryptionTime[1] = total/Runs;

        //AES-256
        total = 0;
        for (int i=2; i < (Runs+2); i++){

            total = total + DecryptionTime[2][i];

        }
        AverageDecryptionTime[2] = total/Runs;

        //RC4
        total = 0;
        for (int i=2; i < (Runs+2); i++){

            total = total + DecryptionTime[3][i];

        }
        AverageDecryptionTime[3] = total/Runs;

        //BF
        total = 0;
        for (int i=2; i < (Runs+2); i++){

            total = total + DecryptionTime[4][i];

        }
        AverageDecryptionTime[4] = total/Runs;

        //Computing Average THETA
        //AES-128
        long tot = 0;
        for (int i=2; i < (Runs+2); i++){

            tot = tot + theta[0][i];

        }
        Averagetheta[0] = tot/Runs;

        //AES-192
        tot = 0;
        for (int i=2; i < (Runs+2); i++){

            tot = tot + theta[1][i];

        }
        Averagetheta[1] = tot/Runs;

        //AES-256
        tot = 0;
        for (int i=2; i < (Runs+2); i++){

            tot = tot + theta[2][i];

        }
        Averagetheta[2] = tot/Runs;

        //RC4
        tot = 0;
        for (int i=2; i < (Runs+2); i++){

            tot = tot + theta[3][i];

        }
        Averagetheta[3] = tot/Runs;

        //BF
        tot = 0;
        for (int i=2; i < (Runs+2); i++){

            tot = tot + theta[4][i];

        }
        Averagetheta[4] = tot/Runs;


        //Printing Average Values
        VerticalSpace();
        System.out.println("Encryption Times : ");
        for (int j = 0; j < 5; j++){

            System.out.println(AverageEncryptionTime[j]);
        }

        VerticalSpace();
        System.out.println("Decryption Times : ");
        for (int j = 0; j < 5; j++){

            System.out.println(AverageDecryptionTime[j]);
        }

        VerticalSpace();
        System.out.println("Theta Values : ");
        for (int j = 0; j < 5; j++){

            System.out.println(Averagetheta[j]);
        }


    }

    public static void CostCalculation(int x) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException{


        String Plaintext = RandomStringGenerator();

        //System.out.println("Plaintext Length: "+Plaintext.length());

        //String EncryptedText = new String(SecurityMechanisms.RC4_encrypt(Plaintext));

        //String EncryptedText = new String(SecurityMechanisms.RC4Encrypt(Plaintext.getBytes(),SECRET_KEY_RC4.getBytes()));

        //byte[] EncryptedBytes = SecurityMechanisms.RC4Encrypt(Plaintext.getBytes(),SECRET_KEY_RC4.getBytes());

        long start_time = System.nanoTime();

        String RC4EncryptedText = SecurityMechanisms.RC4Encrypt(Plaintext,SECRET_KEY_RC4.getBytes());

        long end_time = System.nanoTime();

        //System.out.println("RC4 Encrypted Text : "+RC4EncryptedText);
        long RC4_Te = TimeDifference(start_time,end_time)/1000000;

        long RC4_theta = RC4EncryptedText.length();

        //System.out.println("RC4 Encrypted Text Length: "+RC4EncryptedText.length());

        //System.out.println("RC4 Encrypted Time: "+TimeDifference(start_time,end_time)/1000000);

        start_time = System.nanoTime();

        String BFEncryptedText = SecurityMechanisms.BF_encrypt(Plaintext,SECRET_KEY_RC4);

        end_time = System.nanoTime();

        long BF_Te = TimeDifference(start_time,end_time)/1000000;

        //System.out.println("BF Encrypted Text : "+BFEncryptedText);

        long BF_theta = BFEncryptedText.length();

        //System.out.println("BF Encrypted Text Length: "+BFEncryptedText.length());

        //System.out.println("BF Encrypted Time: "+TimeDifference(start_time,end_time)/1000000);

        start_time = System.nanoTime();

        String AESEncryptedText256 = SecurityMechanisms.AES_Encrypt(Plaintext,SECRET_KEY_RC4,256);

        end_time = System.nanoTime();

        long AES256_Te = TimeDifference(start_time,end_time)/1000000;

        //System.out.println("AES 256 Encrypted Text : "+AESEncryptedText256);

        long AES256_theta = AESEncryptedText256.length();

        //System.out.println("AES 256 Encrypted Text Length: "+AESEncryptedText256.length());

        //System.out.println("AES 256 Encrypted Time: "+TimeDifference(start_time,end_time)/1000000);

        start_time = System.nanoTime();

        String AESEncryptedText192 = SecurityMechanisms.AES_Encrypt(Plaintext,SECRET_KEY_RC4,192);

        end_time = System.nanoTime();

        long AES192_Te = TimeDifference(start_time,end_time)/1000000;

        //System.out.println("AES 192 Encrypted Text : "+AESEncryptedText192);

        long AES192_theta = AESEncryptedText192.length();

        //System.out.println("AES 192 Encrypted Text Length: "+AESEncryptedText192.length());

        //System.out.println("AES 192 Encrypted Time: "+TimeDifference(start_time,end_time)/1000000);

        start_time = System.nanoTime();

        String AESEncryptedText128 = SecurityMechanisms.AES_Encrypt(Plaintext,SECRET_KEY_RC4,128);

        end_time = System.nanoTime();

        long AES128_Te = TimeDifference(start_time,end_time)/1000000;

        //System.out.println("AES 128 Encrypted Text : "+AESEncryptedText128);

        long AES128_theta = AESEncryptedText128.length();

        //System.out.println("AES 128 Encrypted Text Length: "+AESEncryptedText128.length());

        //System.out.println("AES 128 Encrypted Time: "+TimeDifference(start_time,end_time)/1000000);




        //DECRYPTION

        start_time = System.nanoTime();

        String RC4DecryptedText = SecurityMechanisms.RC4Decrypt(RC4EncryptedText,SECRET_KEY_RC4.getBytes());

        end_time = System.nanoTime();

        long RC4_Td = TimeDifference(start_time,end_time)/1000000;

        //System.out.println("RC4 Decrypted Time: "+TimeDifference(start_time,end_time)/1000000);

        start_time = System.nanoTime();

        String AESDecryptedText256 = SecurityMechanisms.AES_Decrypt(AESEncryptedText256,SECRET_KEY_RC4,256);

        end_time = System.nanoTime();

        long AES256_Td = TimeDifference(start_time,end_time)/1000000;

        //System.out.println("AES Decrypted Time 256: "+TimeDifference(start_time,end_time)/1000000);

        start_time = System.nanoTime();

        String AESDecryptedText192 = SecurityMechanisms.AES_Decrypt(AESEncryptedText192,SECRET_KEY_RC4,192);

        end_time = System.nanoTime();

        //System.out.println("AES Decrypted Time 192: "+TimeDifference(start_time,end_time)/1000000);

        long AES192_Td = TimeDifference(start_time,end_time)/1000000;

        start_time = System.nanoTime();

        String AESDecryptedText128 = SecurityMechanisms.AES_Decrypt(AESEncryptedText128,SECRET_KEY_RC4,128);

        end_time = System.nanoTime();

        //System.out.println("AES Decrypted Time 128: "+TimeDifference(start_time,end_time)/1000000);

        long AES128_Td = TimeDifference(start_time,end_time)/1000000;

        start_time = System.nanoTime();

        String BFDecryptedText = SecurityMechanisms.BF_decrypt(BFEncryptedText,SECRET_KEY_RC4);

        end_time = System.nanoTime();

        //System.out.println("BF Decrypted Time: "+TimeDifference(start_time,end_time)/1000000);

        long BF_Td = TimeDifference(start_time,end_time)/1000000;

        VerticalSpace();

        //System.out.println("Values sperated by commas: ");

        VerticalSpace();

        //System.out.println(AES128_Te+","+AES128_Td+","+AES128_theta+","+AES192_Te+","+AES192_Td+","+AES192_theta+","+AES256_Te+","+AES256_Td+","+AES256_theta+","+RC4_Te+","+RC4_Td+","+RC4_theta+","+BF_Te+","+BF_Td+","+BF_theta);

        //Assigning Values to the Vectors

        //ROWS = Encryption Algorithm
        //COLUMNS = Running Instance

        //Encryption Time
        EncryptionTime[0][x] = AES128_Te;
        EncryptionTime[1][x] = AES192_Te;
        EncryptionTime[2][x] = AES256_Te;
        EncryptionTime[3][x] = RC4_Te;
        EncryptionTime[4][x] = BF_Te;

        //Decryption Time
        DecryptionTime[0][x] = AES128_Td;
        DecryptionTime[1][x] = AES192_Td;
        DecryptionTime[2][x] = AES256_Td;
        DecryptionTime[3][x] = RC4_Td;
        DecryptionTime[4][x] = BF_Td;

        //Theta
        theta[0][x] = AES128_theta;
        theta[1][x] = AES192_theta;
        theta[2][x] = AES256_theta;
        theta[3][x] = RC4_theta;
        theta[4][x] = BF_theta;



    }


    public static String RandomStringGenerator() {
        int leftLimit = 97; // letter 'a'
        int rightLimit = 122; // letter 'z'
        long targetStringLength = PlaintextLength;
        Random random = new Random();

        String generatedString = random.ints(leftLimit, rightLimit + 1)
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        return generatedString;
    }

    public static void VerticalSpace(){

        System.out.println("\n\n");
    }


}
