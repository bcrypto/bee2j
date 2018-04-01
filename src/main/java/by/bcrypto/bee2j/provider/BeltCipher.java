package by.bcrypto.bee2j.provider;

import by.bcrypto.bee2j.Bee2Library;
import javax.crypto.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class BeltCipher extends  CipherSpi {

    private int mode;
    private byte[] secretKey;
    private Bee2Library bee2 = Bee2Library.INSTANCE;

    protected void engineSetMode(String s) throws NoSuchAlgorithmException {

    }

    protected void engineSetPadding(String s) throws NoSuchPaddingException {

    }

    protected int engineGetBlockSize() {
        return 128;
    }

    protected int engineGetOutputSize(int i) {
        return 128;
    }

    protected byte[] engineGetIV() {
        return new byte[0];
    }

    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    protected void engineInit(int i, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        mode = i;
        this.secretKey = key.getEncoded();
    }

    protected void engineInit(int i, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {

    }

    protected void engineInit(int i, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {

    }

    protected byte[] engineUpdate(byte[] bytes, int i, int i1) {
        return new byte[0];
    }

    protected int engineUpdate(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException {
        return 0;
    }

    protected byte[] engineDoFinal(byte[] bytes, int i, int i1) throws IllegalBlockSizeException, BadPaddingException {
        byte[] resData = new byte[i1-i];
        byte[] src = new byte[i1 - i];
        System.arraycopy(bytes,i,src,0,i1);
        if(mode == 1) {
            if(bee2.beltECBEncr(resData,src,i1-i,secretKey,secretKey.length)!=0)
                return null;
            return  resData;
        }
        if(mode == 2) {
            if(bee2.beltECBDecr(resData,src,i1-i,secretKey,secretKey.length)!=0)
                return  null;
            return resData;
        }
        return null;
    }

    protected int engineDoFinal(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return 0;
    }
}



