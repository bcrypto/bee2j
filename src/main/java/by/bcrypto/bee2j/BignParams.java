package by.bcrypto.bee2j;

import com.sun.jna.Structure;
import java.security.spec.AlgorithmParameterSpec;

import by.bcrypto.bee2j.constants.XmlIdConstants;

@Structure.FieldOrder({"l", "p", "a", "b", "q", "yG", "seed"})
public class BignParams extends Structure implements Structure.ByReference, AlgorithmParameterSpec {
    public long l;		/*!< уровень стойкости (128, 192 или 256) */
    public byte[] p = new byte[64];	/*!< модуль p */
    public byte[] a = new byte[64];	/*!< коэффициент a */
    public byte[] b = new byte[64];	/*!< коэффициент b */
    public byte[] q = new byte[64];	/*!< порядок q */
    public byte[] yG = new byte[64];	/*!< y-координата точки G */
    public byte[] seed = new byte[8];  /*!< параметр seed */

    public BignParams(long level) {
        String curve_oid = getCurveOid(level);

        int res = Bee2Library.INSTANCE.bignParamsStd(this, curve_oid);
        if (res!=0)
            throw new RuntimeException("Params were not loaded, code is " + res);

        assert is_valid(this);
    }

    public static String getCurveOid(long level) {
         switch ((int)level) {
             case 128: {return "1.2.112.0.2.0.34.101.45.3.1";}
             case 192: {return "1.2.112.0.2.0.34.101.45.3.2";}
             case 256: {return "1.2.112.0.2.0.34.101.45.3.3";}
             default: throw new IllegalArgumentException("Level " + level + " is invalid");
        }
    }

    public static String getCurveXmlID(long level) {
        switch ((int)level) {
            case 128: {return XmlIdConstants.Bign256;}
            case 192: {return XmlIdConstants.Bign384;}
            case 256: {return XmlIdConstants.Bign512;}
            default: throw new IllegalArgumentException("Level " + level + " is invalid");
       }
    }

    public static int getLevel(String curveXmlID) {
        switch (curveXmlID) {
            case XmlIdConstants.Bign256: {return 128;}
            case XmlIdConstants.Bign384: {return 192;}
            case XmlIdConstants.Bign512: {return 256;}
            default: throw new IllegalArgumentException("ID " + curveXmlID + " is invalid");
        }
    }

    public static boolean is_valid(BignParams bignParams) {
        return Bee2Library.INSTANCE.bignParamsVal(bignParams) == 0;
    }
}