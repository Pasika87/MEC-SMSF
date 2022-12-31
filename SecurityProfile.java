package MigrationModel;


import java.util.ArrayList;
import java.util.LinkedList;

public class SecurityProfile {


    public static Long SPI;
    public static String K_M;
    public static int ActiveLayers;
    public static String LayerIndex;

    LinkedList<SPLayer> LL_SPL = new LinkedList<SPLayer>();
    //public ArrayList<SPLayer>;

    public static boolean TunnelMode = false;

    public SecurityProfile(Long spi, String K_M) {

        SPI = spi;

        System.out.println("Security Profile is Forming....");
        System.out.println("Security Profile Index (SPI) : "+SPI);


    }

    public void AddLayer(int index, String ALGO, int KEY_SIZE, String BCM, String PADDING, String KEY){

        SPLayer layer = new SPLayer(index, ALGO, KEY_SIZE, BCM, PADDING, KEY);
        LL_SPL.add(layer);

    }


}
