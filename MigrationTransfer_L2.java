package MigrationModel;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jcajce.provider.symmetric.AES;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.sql.SQLOutput;
import java.sql.Time;
import java.util.ArrayList;
import java.util.Base64;
//import org.apache.commons.codec.binary.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class MigrationTransfer_L2 {

    public static long Start_time;
    public static long Intermediary_time;
    public static long End_time;
    public static long File_Send_Start_time;
    public static long File_Send_End_time;
    public static long File_Receive_Start_time;
    public static long File_Receive_End_time;
    public static Long Process_time_Send;
    public static Long Process_time_Receive;

    public static int file_segment_size = 32*1024; //KB
    public static int max_data_segment_size = 1024*1024; //1 MB
    public static int increment =0;

    public static DataOutputStream dataOutputStream = null;
    public static DataInputStream dataInputStream = null;

    public static int x = 0;

    public static final String SALT = "ssshhhhhhhhhhh!!!!ssshhhhhhhhhhh!!!!";

    private static final String STREAM_ENCRYPTION_ALGORITHM = "ARCFOUR"; // or "RC4"

    public static String SECRET_KEY_RC4 = "ThisIsTheRC4SecretKey";

    public static void Migration(Socket socket, String SECRET_KEY, int AES_Key_Length, String path, String filename){

        try {

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            //dataInputStream = new DataInputStream(socket.getInputStream());
            //dataOutputStream = new DataOutputStream(socket.getOutputStream());

            Start_time = System.nanoTime();

            System.out.println("Initiating Migration of the container image.....");
            VerticalSpace();

            System.out.println("FILE COMPRESSION BEGINS.........");
            //Compressing the Container Image File
            Compress(filename,path);

            End_time = System.nanoTime();

            System.out.println("FILE COMPRESSION ENDS.........");

            System.out.println("Compression Delay [ms] : "+(TimeDifference(Start_time,End_time)/1000000));

            VerticalSpace();

            //Encoding Phase
            //Reading compressed file
            int bytes = 0;
            File CompressedFile = new File(path+"/compressed.zip");

            System.out.println("FILE ENCODING STARTS.........");

            Intermediary_time = System.nanoTime();

            //Converting the Compressed file into Base64Encoding...
            String EncodedString = encodeFileToBase64String(CompressedFile);

            System.out.println("FILE ENCODING ENDS.........");

            End_time = System.nanoTime();

            System.out.println("Time taken for the Base64 Encoding Process : "+TimeDifference(Intermediary_time,End_time)/1000000);

            //System.out.println("Encoded File : "+EncodedString);
            long CompressedSize = Files.size(Paths.get(path+"/"+"compressed.zip"));
            long EncodedSize = EncodedString.length();

            System.out.println("Size of the Encoded String [bytes] : "+EncodedSize);

            System.out.println("Size Increment of the Encoding Process : "+((EncodedSize - CompressedSize)/CompressedSize)*100);

            VerticalSpace();

            //Fragmentation Phase

            System.out.println("FILE FRAGMENTING STARTS.........");

            Intermediary_time = System.nanoTime();

            ArrayList<String> Encoded_Compressed_String_FileArray = new ArrayList<>();

            Encoded_Compressed_String_FileArray = Fragmenting(EncodedString,max_data_segment_size);

            End_time = System.nanoTime();

            System.out.println("Time taken for the Fragmentation Process : "+TimeDifference(Intermediary_time,End_time)/1000000);

            System.out.println("FILE FRAGMENTING ENDS.........");

            VerticalSpace();

            //File Migration Phase

            int stagesize = Encoded_Compressed_String_FileArray.size()/4;

            System.out.println("Stagesize : "+stagesize);

            Intermediary_time = System.nanoTime();

            int x = 1;

            for (int i =0; i < Encoded_Compressed_String_FileArray.size(); i++){

                if (i < stagesize){

                    //Hash = SHA
                    String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,256)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,192)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,128)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.RC4Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY_RC4.getBytes())+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.BF_encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));

                    //Hash = Keccak
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,256)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,192)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,128)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.RC4Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY_RC4.getBytes())+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.BF_encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));

                    out.println(Message);
                    System.out.println("Encryption+Hash Message "+i+" sent......");

                } else if (i < 2*stagesize){

                    if( x == 1) {
                        System.out.println("...............SECURITY PROFILE SWITCHED.............");
                        x++;
                    }

                    //Hash = SHA
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,256)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,192)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,128)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.RC4Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY_RC4.getBytes())+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.BF_encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));

                    //Hash = Keccak
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,256)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,192)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,128)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.RC4Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY_RC4.getBytes())+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.BF_encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));

                    out.println(Message);
                    System.out.println("Encryption+Hash Message \"+i+\" sent......");


                }else if (i < 3* stagesize){

                    if( x == 2) {
                        System.out.println("...............SECURITY PROFILE SWITCHED.............");
                        x++;
                    }

                    //Hash = SHA
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,256)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,192)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,128)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.RC4Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY_RC4.getBytes())+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.BF_encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));

                    //Hash = Keccak
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,256)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,192)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,128)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.RC4Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY_RC4.getBytes())+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.BF_encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));

                    out.println(Message);
                    System.out.println("Encryption+Hash Message \"+i+\" sent......");

                }else {

                    if( x == 3) {
                        System.out.println("...............SECURITY PROFILE SWITCHED.............");
                        x++;
                    }

                    //Hash = SHA
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,256)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,192)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,128)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    String Message = SecurityMechanisms.RC4Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY_RC4.getBytes())+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.BF_encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY)+" "+SecurityMechanisms.Hash(Encoded_Compressed_String_FileArray.get(i));

                    //Hash = Keccak
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,256)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,192)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.AES_Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY,128)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.RC4Encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY_RC4.getBytes())+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));
                    //String Message = SecurityMechanisms.BF_encrypt(Encoded_Compressed_String_FileArray.get(i),SECRET_KEY)+" "+SecurityMechanisms.hashKeccak(Encoded_Compressed_String_FileArray.get(i));

                    out.println(Message);
                    System.out.println("Encryption+Hash Message \"+i+\" sent......");

                }


            }

            out.println("FINISH");

            End_time = System.nanoTime();

            System.out.println("FILE MIGRATION ENDS.........");

            System.out.println("Migration Delay [ms] : "+(TimeDifference(Intermediary_time,End_time)/1000000));

            VerticalSpace();

            Process_time_Send = TimeDifference(Start_time, End_time)/1000000;

            System.out.println("Time taken for migration - sending Processing [ms]: "+Process_time_Send);


        }catch (Exception e){
            e.printStackTrace();
        }


    }

    public static void Receiving(ServerSocket serverSocket, String SECRET_KEY, int AES_Key_Length, String path, String filename){

        try{

            System.out.println("listening to port:9000");
            Socket clientSocket = serverSocket.accept();
            System.out.println(clientSocket+" connected.");

            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

            //dataInputStream = new DataInputStream(clientSocket.getInputStream());
            //dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());

            Start_time = System.nanoTime();

            System.out.println("Receiving the container image.....");
            VerticalSpace();


            //Receiving the Encrypted File and Storing in a ArrayList
            Intermediary_time = System.nanoTime();

            ArrayList<String> Received_Encrypted_FileArray = new ArrayList<>();
            ArrayList<String> Received_Hash = new ArrayList<>();
            ArrayList<String> Received_Decrypted_FileArray = new ArrayList<>();
            int j=1;

            while (true){
                String Message = in.readLine();

                if (Message.startsWith("FINISH")){
                    break;
                }else{

                    String Messages[]= Message.split(" ");

                    if(j ==1){
                        Intermediary_time = System.nanoTime();
                    }


                    Received_Encrypted_FileArray.add(Messages[0]);
                    Received_Hash.add(Messages[1]);
                    System.out.println("Received the Message "+j+".....");
                    j++;

                }
            }

            End_time = System.nanoTime();

            System.out.println("MIGRATION PHASE FINISHED");

            System.out.println("Time taken for migration - receiving Process [ms]: "+TimeDifference(Intermediary_time,End_time)/1000000);

            clientSocket.close();

            System.out.println("Received Number of Messages : "+Received_Encrypted_FileArray.size());

            VerticalSpace();

            int stagesize = Received_Encrypted_FileArray.size()/4;

            System.out.println("Stagesize : "+stagesize);

            Intermediary_time = System.nanoTime();

            //Decryption Phase
            String DecryptedEncodedFile = "";

            int x = 1;

            for (int i =0; i < Received_Encrypted_FileArray.size(); i++) {

                if(i < stagesize){

                    //Decryption
                    String Decrypted_Message = SecurityMechanisms.AES_Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY,256);
                    //String Decrypted_Message = SecurityMechanisms.AES_Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY,192);
                    //String Decrypted_Message = SecurityMechanisms.AES_Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY,128);
                    //String Decrypted_Message = SecurityMechanisms.RC4Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY_RC4.getBytes());
                    //String Decrypted_Message = SecurityMechanisms.BF_decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY);

                    //Integrity Checking

                    String MAC = SecurityMechanisms.Hash(Decrypted_Message);
                    //String MAC = SecurityMechanisms.hashKeccak(Decrypted_Message);

                        if (MAC.matches(Received_Hash.get(i))){

                            System.out.println("INTEGRITY Assured...........");
                            Received_Decrypted_FileArray.add(Decrypted_Message);

                        }else {

                            System.out.println("......................ALERT  :  Integrity of the Migration Compromised.............");
                            VerticalSpace();

                        }

                    }else if(i < 2*stagesize){

                    if( x == 1) {
                        System.out.println("...............SECURITY PROFILE SWITCHED.............");
                        x++;
                    }

                    //Decryption
                    //String Decrypted_Message = SecurityMechanisms.AES_Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY,256);
                    String Decrypted_Message = SecurityMechanisms.AES_Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY,192);
                    //String Decrypted_Message = SecurityMechanisms.AES_Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY,128);
                    //String Decrypted_Message = SecurityMechanisms.RC4Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY_RC4.getBytes());
                    //String Decrypted_Message = SecurityMechanisms.BF_decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY);

                    //Integrity Checking

                    String MAC = SecurityMechanisms.Hash(Decrypted_Message);
                    //String MAC = SecurityMechanisms.hashKeccak(Decrypted_Message);

                    if (MAC.matches(Received_Hash.get(i))){

                        System.out.println("INTEGRITY Assured...........");
                        Received_Decrypted_FileArray.add(Decrypted_Message);

                    }else {

                        System.out.println("......................ALERT  :  Integrity of the Migration Compromised.............");
                        VerticalSpace();

                    }

                }else if(i < 3* stagesize){

                    if( x == 2) {
                        System.out.println("...............SECURITY PROFILE SWITCHED.............");
                        x++;
                    }

                    //Decryption
                    //String Decrypted_Message = SecurityMechanisms.AES_Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY,256);
                    //String Decrypted_Message = SecurityMechanisms.AES_Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY,192);
                    String Decrypted_Message = SecurityMechanisms.AES_Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY,128);
                    //String Decrypted_Message = SecurityMechanisms.RC4Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY_RC4.getBytes());
                    //String Decrypted_Message = SecurityMechanisms.BF_decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY);

                    //Integrity Checking

                    String MAC = SecurityMechanisms.Hash(Decrypted_Message);
                    //String MAC = SecurityMechanisms.hashKeccak(Decrypted_Message);

                    if (MAC.matches(Received_Hash.get(i))){

                        System.out.println("INTEGRITY Assured...........");
                        Received_Decrypted_FileArray.add(Decrypted_Message);

                    }else {

                        System.out.println("......................ALERT  :  Integrity of the Migration Compromised.............");
                        VerticalSpace();

                    }

                }else {

                    if( x == 3) {
                        System.out.println("...............SECURITY PROFILE SWITCHED.............");
                        x++;
                    }

                    //Decryption
                    //String Decrypted_Message = SecurityMechanisms.AES_Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY,256);
                    //String Decrypted_Message = SecurityMechanisms.AES_Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY,192);
                    //String Decrypted_Message = SecurityMechanisms.AES_Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY,128);
                    String Decrypted_Message = SecurityMechanisms.RC4Decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY_RC4.getBytes());
                    //String Decrypted_Message = SecurityMechanisms.BF_decrypt(Received_Encrypted_FileArray.get(i),SECRET_KEY);

                    //Integrity Checking

                    String MAC = SecurityMechanisms.Hash(Decrypted_Message);
                    //String MAC = SecurityMechanisms.hashKeccak(Decrypted_Message);

                    if (MAC.matches(Received_Hash.get(i))){

                        System.out.println("INTEGRITY Assured...........");
                        Received_Decrypted_FileArray.add(Decrypted_Message);

                    }else {

                        System.out.println("......................ALERT  :  Integrity of the Migration Compromised.............");
                        VerticalSpace();

                    }

                }



            }

            System.out.println("DECRYPTION COMPLETE......");


            for (int i =0; i < Received_Decrypted_FileArray.size(); i++) {

                DecryptedEncodedFile = DecryptedEncodedFile + Received_Decrypted_FileArray.get(i);

            }

            End_time = System.nanoTime();

            System.out.println("File Concatination/ Formation COMPLETE...........");

            System.out.println("Time taken for Decryption [ms]: "+TimeDifference(Intermediary_time,End_time)/1000000);

            VerticalSpace();

            //Base64 Decoding Phase
            System.out.println("FILE DECODING BEGINS.........");
            Intermediary_time = System.nanoTime();
            byte[] decodedByteArray = Base64.getDecoder().decode(DecryptedEncodedFile);
            FileUtils.writeByteArrayToFile(new File(path+"/compressed.zip"), decodedByteArray);

            End_time = System.nanoTime();
            System.out.println("FILE DECODING ENDS.........");

            System.out.println("Time taken for Base64 Decoding [ms] : "+ (TimeDifference(Intermediary_time, End_time)/1000000));

            VerticalSpace();

            System.out.println("FILE DECOMPRESSION BEGINS.........");
            Intermediary_time = System.nanoTime();

            Decompress("compressed.zip",path,path);

            End_time = System.nanoTime();
            System.out.println("FILE DECOMPRESSION ENDS.........");

            System.out.println("Time taken for Decompression [ms] : "+ (TimeDifference(Intermediary_time, End_time)/1000000));

            VerticalSpace();

            Process_time_Receive = TimeDifference(Start_time, End_time)/1000000;

            System.out.println("Process Time [ms]: "+Process_time_Receive);



        } catch (Exception e){
            e.printStackTrace();
        }



    }

    public static String encodeFileToBase64String(File file){

        try {
            byte[] fileContent = Files.readAllBytes(file.toPath());
            return Base64.getEncoder().encodeToString(fileContent);
        } catch (IOException e) {
            throw new IllegalStateException("could not read file " + file, e);
        }

    }

    public static ArrayList<String> Fragmenting(String encodedString, int fragmentSize){

        ArrayList<String> FragmentedArray =  new ArrayList<>();
        int index =0;
        while(index < encodedString.length()){
            FragmentedArray.add(encodedString.substring(index, Math.min(index + fragmentSize,encodedString.length())));
            index += fragmentSize;
        }

        System.out.println("Number of Fragmented Array Elements : "+FragmentedArray.size());
        return FragmentedArray;
    }

    public static void Compress(String sourcefile, String path) throws FileNotFoundException, IOException{

        FileOutputStream fos = new FileOutputStream(path+"/"+"compressed.zip");
        ZipOutputStream zipOut = new ZipOutputStream(fos);
        File fileToZip = new File(path+"/"+sourcefile);
        FileInputStream fis = new FileInputStream(fileToZip);
        ZipEntry zipEntry = new ZipEntry(fileToZip.getName());
        zipOut.putNextEntry(zipEntry);
        byte[] bytes = new byte[1024];
        int length;
        while((length = fis.read(bytes)) >= 0) {
            zipOut.write(bytes, 0, length);
        }
        zipOut.close();
        fis.close();
        fos.close();

        long sourcefilesize = fileToZip.length();
        long compressedfilesize = Files.size(Paths.get(path+"/"+"compressed.zip"));
        double compression = (double)(sourcefilesize - compressedfilesize);
        double Compression_Ratio = ((double)compression/(double)sourcefilesize)*100;

        System.out.println("Size of the Source File : "+sourcefilesize);
        System.out.println("Size of the Compressed File : "+compressedfilesize);
        System.out.println("Compression [MB] : "+compression/(8*1000000));
        System.out.println("Compression Ratio : "+Compression_Ratio);

        VerticalSpace();


    }

    public static void Decompress(String sourcefile, String sourcepath, String destinationpath) throws FileNotFoundException, IOException{

        String fileZip = sourcepath+"/"+sourcefile;
        File destDir = new File(destinationpath);
        byte[] buffer = new byte[1024];
        ZipInputStream zis = new ZipInputStream(new FileInputStream(fileZip));
        ZipEntry zipEntry = zis.getNextEntry();
        while (zipEntry != null) {
            File newFile = newFile(destDir, zipEntry);
            if (zipEntry.isDirectory()) {
                if (!newFile.isDirectory() && !newFile.mkdirs()) {
                    throw new IOException("Failed to create directory " + newFile);
                }
            } else {
                // fix for Windows-created archives
                File parent = newFile.getParentFile();
                if (!parent.isDirectory() && !parent.mkdirs()) {
                    throw new IOException("Failed to create directory " + parent);
                }

                // write file content
                FileOutputStream fos = new FileOutputStream(newFile);
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
                fos.close();
            }
            zipEntry = zis.getNextEntry();
        }
        zis.closeEntry();
        zis.close();


    }

    public static File newFile(File destinationDir, ZipEntry zipEntry) throws IOException {
        File destFile = new File(destinationDir, zipEntry.getName());

        String destDirPath = destinationDir.getCanonicalPath();
        String destFilePath = destFile.getCanonicalPath();

        if (!destFilePath.startsWith(destDirPath + File.separator)) {
            throw new IOException("Entry is outside of the target dir: " + zipEntry.getName());
        }

        return destFile;
    }



    public static String Concatenate(byte[] CompressedFileInBytes, int increment){

        String ConcatenatedMessage = "";
        int size = CompressedFileInBytes.length;

        if(CompressedFileInBytes.length < max_data_segment_size){

            for (int i = 0; i < size; i++) {

                ConcatenatedMessage = ConcatenatedMessage + CompressedFileInBytes[i];

            }

        }else {

            for (int i = 0; i < max_data_segment_size; i++) {

                ConcatenatedMessage = ConcatenatedMessage + CompressedFileInBytes[increment + i];

                //System.out.println("Concatenated Output : "+i);

            }
        }

        System.out.println("Concatenated Message : "+ConcatenatedMessage);

        return ConcatenatedMessage;

    }


    public static long TimeDifference(long start_time, long end_time){

        return (end_time - start_time);
    }

    public static void VerticalSpace(){

        System.out.println("\n\n");
    }



}
