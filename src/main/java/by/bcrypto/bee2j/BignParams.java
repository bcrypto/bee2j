package by.bcrypto.bee2j;

import com.sun.jna.Structure;

@Structure.FieldOrder({"l", "p", "a", "b", "q", "yG", "seed"})
public class BignParams extends Structure implements Structure.ByReference {
    public int l;		/*!< уровень стойкости (128, 192 или 256) */
    public byte[] p = new byte[64];	/*!< модуль p */
    public byte[] a = new byte[64];	/*!< коэффициент a */
    public byte[] b = new byte[64];	/*!< коэффициент b */
    public byte[] q = new byte[64];	/*!< порядок q */
    public byte[] yG = new byte[64];	/*!< y-координата точки G */
    public byte[] seed = new byte[8];  /*!< параметр seed */

    public BignParams(int level) {
        String curve_name;
        curve_name = getCurveName(level);

        int res = Bee2Library.INSTANCE.bignStdParams(this, curve_name);
        if (res!=0)
            throw new RuntimeException("Params were not loaded, code is " + res);

        assert is_valid(this);
    }
    public static String getCurveName(int level) {
        return switch (level) {
            case 128 -> "1.2.112.0.2.0.34.101.45.3.1";
            case 192 -> "1.2.112.0.2.0.34.101.45.3.2";
            case 256 -> "1.2.112.0.2.0.34.101.45.3.3";
            default -> throw new IllegalArgumentException("Level " + level + " is invalid");
        };
    }

    public static boolean is_valid(BignParams bignParams) {
        return Bee2Library.INSTANCE.bignValParams(bignParams) == 0;

    }

}