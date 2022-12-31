package MigrationModel;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import org.apache.commons.io.FileUtils;

import java.nio.file.Files;
import java.nio.file.Paths;

public class Test extends MigrationTransfer {

    public static final String SECRET_KEY = "my_super_secret_key_ho_ho_ho";
    public static int AES_Key_Length = 256; //bits

    public static void main(String[] args) throws IOException {

        ArrayList<String> EncodedString = new ArrayList<>();

        int fragmentSize = 32*1024; //32KB

        String filePath = "E:/gNBs/tpot_arm64.iso";
        String fileName = "tpot_arm64.iso";

        File file = new File(fileName);

        byte[] fileContent = FileUtils.readFileToByteArray(new File(filePath));

        MigrationTransfer.Start_time = System.nanoTime();
        String encodedString = Base64.getEncoder().encodeToString(fileContent);
        //String encodedString = new String(encoded, StandardCharsets.US_ASCII);
        MigrationTransfer.End_time = System.nanoTime();

        System.out.println("Time taken for the Base64 Conversion : "+MigrationTransfer.TimeDifference(Start_time,End_time)/1000000);

        System.out.println("Encoded File : "+encodedString);

        System.out.println("Size of the Encoded String [bytes] : "+encodedString.length());

        int index=0;

        MigrationTransfer.Start_time = System.nanoTime();
        while(index < encodedString.length()){
            EncodedString.add(encodedString.substring(index, Math.min(index + fragmentSize,encodedString.length())));
            index += fragmentSize;

        }
        MigrationTransfer.End_time = System.nanoTime();


        System.out.println("Time taken for the Splitting Process : "+MigrationTransfer.TimeDifference(Start_time,End_time)/1000000);

        System.out.println("First Message : "+EncodedString.get(0));
        System.out.println("Size of the First Message [bytes]: "+EncodedString.get(0).length());

        //Encrypting first encoded string
        String EncryptedString = SecurityMechanisms.AES_Encrypt(EncodedString.get(1),SECRET_KEY, AES_Key_Length);

        System.out.println("Encrypted String : "+EncryptedString);

    }


}
