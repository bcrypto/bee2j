package by.bcrypto.bee2j.provider;

import by.bcrypto.bee2j.Bee2Library;
import javax.crypto.MacSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;

public class BeltMAC extends MacSpi {

    byte[] theta;
    ArrayList<Byte> data = new ArrayList<Byte>();
    Bee2Library bee2 = Bee2Library.INSTANCE;

    protected int engineGetMacLength() {
        return 8;
    }

    protected void engineInit(Key key, AlgorithmParameterSpec algorithmParameterSpec) throws InvalidKeyException, InvalidAlgorithmParameterException {
        theta = key.getEncoded();
    }

    protected void engineUpdate(byte b) {
        data.add(b);
    }

    protected void engineUpdate(byte[] bytes, int i, int i1) {
        for (int j = i; j < i  + i1; j++)
            data.add(bytes[j]);
    }

    protected byte[] engineDoFinal() {
        byte[] res = new byte[8];
        if(bee2.beltMAC(res,Util.bytes(data),Util.bytes(data).length,theta,theta.length)!=0)
            return null;
        return res;
    }

    protected void engineReset() {
        data = new ArrayList<Byte>();
        theta = null;
    }
}
