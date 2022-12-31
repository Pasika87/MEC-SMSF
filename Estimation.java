package MigrationModel;

public class Estimation {

    public static long input = 10000;

    public static double EstimateSecurityCost(String ALGO, int Key_Size, String BCM, String Padding, long I, double RB){
//RB = Residual Bandwidth
        double SO;
        double SC = 0; // Security Cost
        double E_time;
        double D_time;

        switch(ALGO){

            case "AES":
                SO = Security_Overhead_AES(input, Key_Size, BCM, Padding);
                E_time = EncryptionTime_AES(input,Key_Size,BCM,Padding);
                D_time = EncryptionTime_AES(input,Key_Size,BCM,Padding);

                SC = E_time + D_time + (SO / RB);
                break;

            case "RSA":

            case "BF":

            case "kyber":

            case "SHA":

            case "Keccak":



        }

        return SC;
    }


// Aggregated Security Overhead
    public static double Security_Overhead_AES (long I, int Key_Size, String BCM, String Padding) {

        long I_hat = I;
        long I_dash = I;
        double O = I;
        long O_min = I;
        long O_max = I;
        long delta;
        long divisor;


        //PKCS5Padding and CBC/ ECB
        if((Padding == "PKCS5Padding") && (BCM != "CTR")) {

            O_min = 24;
            delta = 20;
            divisor = 48;
            O_max = O_min + 2 * delta;

            if (I < 48) {
                I_hat = 0;
                I_dash = I;
            } else {
                I_hat = Math.round(I / divisor);
                I_dash = (I % divisor);
            }

            O = O_max * I_hat;

            if (I_dash < 16) {
                O = O + O_min;
            } else if (I_dash < 32) {

                O = O + O_min + delta;
            } else {
                O = O + O_min + 2 * delta;
            }

        } else if((Padding == "NoPadding") && (BCM == "CBC")) {

            O_min = 24;
            delta = 20;
            divisor = 48;

            if( (I % 16) == 0) {

                O_max = O_min + 2 * delta;

                if (I < 64) {
                    I_hat = 0;
                    I_dash = I;
                } else {
                    I_hat = Math.round(I / divisor);
                    I_dash = (I % divisor);
                }

                O = O_max * I_hat;

                if (I_dash == 16) {
                    O = O + O_min;
                } else if (I_dash == 32) {

                    O = O + O_min + delta;
                } else {
                    O = O + O_min + 2 * delta;
                }

            } else {

                System.out.println("The Input Size is not divisable by 16 : Cannot Perform Encryption.......");
            }

            //CTR MODE
        }else{

            O_min = 4;
            divisor = 3;

            I_hat = Math.round(I/divisor);
            O = I_hat * O_min;

        }

        return (O - I);

    }

    public static double EncryptionTime_AES(long I, int Key_Size, String BCM, String Padding){

        // y = m.x + c
        double c = 10;
        double m = 3;

        return ((m*I)+c);
    }

    public static double Security_Overhead_BF(long I){

        long I_hat = I;
        long I_dash = I;
        double O = I;
        long O_min = I;
        long O_max = I;
        long delta;
        long divisor;


        O_min = 12;
        delta = 8;
        divisor = 24;

        O_max = (2 * O_min + delta);

        if (I < 24) {
            I_hat = 0;
            I_dash = I;
        } else {
            I_hat = Math.round(I / divisor);
            I_dash = (I % divisor);
        }

        O = O_max * I_hat;

        if (I_dash < 8) {
            O = O + O_min;
        } else if (I_dash < 16) {

            O = O + 2 * O_min;
        } else {
            O = O + 2 * O_min + delta;
        }

        return (O - I);

    }

    /*
    public static void main (String []args){

        System.out.println("Output Size : "+Security_Overhead_AES(input,128,"CBC", "PKCS5Padding"));

    }
*/

}
