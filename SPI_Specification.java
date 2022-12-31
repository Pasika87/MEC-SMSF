package MigrationModel;

import java.util.LinkedList;

public class SPI_Specification {

    static long SPI;
    String KF;

    public static String ALGO;
    public static int KEY;
    public static String BCM;
    public static String PADDING;

    static int LayerIndex = 0;

    LinkedList<SecurityProfile> LL_SP = new LinkedList<SecurityProfile>();

    public SecurityProfile SPI_Specification(long spi, String K_M) {

        SecurityProfile SP = null;

        if (SPI == 0001) {

            //Layer 0
            LayerIndex = 0;
            ALGO = "AES";
            KEY = 128;
            BCM = "CBC";
            PADDING = "PKCS5PADDING";

            SP = new SecurityProfile(SPI, K_M);
            SP.AddLayer(LayerIndex, ALGO,KEY,BCM, PADDING,K_M);


        }else if (SPI == 0002) {

            //Layer 0
            LayerIndex = 0;
            ALGO = "AES";
            KEY = 192;
            BCM = "CBC";
            PADDING = "PKCS5PADDING";

            SP = new SecurityProfile(SPI, K_M);
            SP.AddLayer(LayerIndex, ALGO,KEY,BCM, PADDING,K_M);


        }else if (SPI == 0003) {

            //Layer 0
            LayerIndex = 0;
            ALGO = "AES";
            KEY = 256;
            BCM = "CBC";
            PADDING = "PKCS5PADDING";

            SP = new SecurityProfile(SPI, K_M);
            SP.AddLayer(LayerIndex, ALGO,KEY,BCM, PADDING,K_M);

        }else if (SPI == 0004){

            //Layer 0
            LayerIndex = 0;
            ALGO = "AES";
            KEY = 128;
            BCM = "CBC";
            PADDING = "PKCS5PADDING";

            SP = new SecurityProfile(SPI, K_M);
            SP.AddLayer(LayerIndex, ALGO,KEY,BCM, PADDING,K_M);

            //Layer 1
            LayerIndex = 1;
            ALGO = "SHA";
            KEY = 1;
            BCM = null;
            PADDING = null;

            SP = new SecurityProfile(SPI, K_M);
            SP.AddLayer(LayerIndex, ALGO,KEY,BCM, PADDING,K_M);

        }else if (SPI == 0005){

            //Layer 0
            LayerIndex = 0;
            ALGO = "AES";
            KEY = 128;
            BCM = "CBC";
            PADDING = "PKCS5PADDING";

            SP = new SecurityProfile(SPI, K_M);
            SP.AddLayer(LayerIndex, ALGO,KEY,BCM, PADDING,K_M);

            //Layer 1
            LayerIndex = 1;
            ALGO = "SHA";
            KEY = 256;
            BCM = null;
            PADDING = null;

            SP = new SecurityProfile(SPI, K_M);
            SP.AddLayer(LayerIndex, ALGO,KEY,BCM, PADDING,K_M);

        } else{

            System.out.println("The SPI is not specified in the SPI Specification..............");
        }

        return SP;
    }

}
