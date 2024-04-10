package by.bcrypto.bee2j.provider.signature;

import java.security.*;
import java.util.ArrayList;
import by.bcrypto.bee2j.Bee2Library;
import by.bcrypto.bee2j.BignParams;
import by.bcrypto.bee2j.constants.OidConstants;
import by.bcrypto.bee2j.provider.BignPrivateKey;
import by.bcrypto.bee2j.provider.BignPublicKey;
import by.bcrypto.bee2j.provider.Util;
import com.sun.jna.ptr.IntByReference;

public class BignWithBeltSignature extends SignatureSpi {

    //private int state;
    private BignPrivateKey privateKey;
    private BignPublicKey publicKey;
    private ArrayList<Byte> data = new ArrayList<Byte>();
    private BignParams params;
    private Bee2Library bee2 = Bee2Library.INSTANCE;
    private Bee2Library.IRngFunction rng = new Bee2Library.BrngFuncForPK();
    private byte[] brng_state = new byte[1024];
    //0 - sign
    //1 - verify

    public Bee2Library.IRngFunction getRng() {
        return rng;
    }

    public void setRng(Bee2Library.IRngFunction rng) {
        this.rng = rng;
    }

    protected void engineInitVerify(PublicKey publicKey) {
        data = new ArrayList<Byte>();
        //this.state = 1;
        this.publicKey = (BignPublicKey) publicKey;
        if (this.publicKey.getBytes().length * 2 == 128) {
            params = new BignParams(128);
            return;
        }
        if (this.publicKey.getBytes().length * 2 == 192) {
            params = new BignParams(192);
            return;
        }
        if (this.publicKey.getBytes().length * 2 == 256) {
            params = new BignParams(256);
            return;
        }
    }

    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        data = new ArrayList<>();
        //this.state = 0;
        this.privateKey = (BignPrivateKey) privateKey;
        if (this.privateKey.getBytes().length * 4 == 128) {
            params = new BignParams(128);
            return;
        }
        if (this.privateKey.getBytes().length * 4 == 192) {
            params = new BignParams(192);
            return;
        }
        if (this.privateKey.getBytes().length * 4 == 256) {
            params = new BignParams(256);
            return;
        }
    }

    protected void engineUpdate(byte b) {
        data.add(b);
    }

    protected void engineUpdate(byte[] b, int off, int len) {
        for (int i = off; i < len; i++) {
            data.add(b[i]);
        }
    }

    protected byte[] engineSign() {
        byte[] sig = new byte[3 * params.l / 8];
        byte[] oid_der = new byte[128];
        byte[] hash = new byte[32];
        byte[] byte_data = Util.bytes(data);
        bee2.beltHash(hash, byte_data, byte_data.length);
        IntByReference pointer = new IntByReference(128);
        if (bee2.bignOidToDER(oid_der, pointer, OidConstants.Belt) != 0)
            return null;
        if (bee2.bignSign(sig, params, oid_der, 11, hash, privateKey.getBytes(), rng, brng_state) != 0)
            return null;

        return sig;
    }

    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        byte[] oid_der = new byte[11];
        byte[] hash = new byte[32];
        byte[] byte_data = Util.bytes(data);

        bee2.beltHash(hash, byte_data, byte_data.length);
        IntByReference pointer = new IntByReference(params.l);
        if (bee2.bignOidToDER(oid_der, pointer, OidConstants.Belt) != 0)
            return false;
        var result = bee2.bignVerify(params, oid_der, 11, hash, sigBytes, publicKey.getBytes());
        if (result == 0)
            return true;
        return false;
    }

    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {

    }

    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }
}
