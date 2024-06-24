package by.bcrypto.bee2j.provider.signature;

import java.security.*;
import java.util.ArrayList;

import com.sun.jna.ptr.LongByReference;

import by.bcrypto.bee2j.Bee2Library;
import by.bcrypto.bee2j.BignParams;
import by.bcrypto.bee2j.provider.*;

public abstract class BignSignature extends SignatureSpi{

    protected BignPrivateKey privateKey;
    protected BignPublicKey publicKey;
    protected ArrayList<Byte> data = new ArrayList<Byte>();
    protected BignParams params;
    protected Bee2Library bee2 = Bee2Library.INSTANCE;
    protected Bee2Library.IRngFunction rng = new Bee2Library.BrngFuncForPK();
    protected byte[] brng_state = new byte[1024];

    abstract public String getHashAlgorithm();
    abstract public String getHashOid();

    public Bee2Library.IRngFunction getRng() {
        return rng;
    }

    public void setRng(Bee2Library.IRngFunction rng) {
        this.rng = rng;
    }

    protected void engineInitVerify(PublicKey publicKey) {
        data = new ArrayList<Byte>();
        this.publicKey = (BignPublicKey) publicKey;
        int level = this.publicKey.getBytes().length * 2;
        if ((level == 128) || (level == 192) || (level == 256))
            params = new BignParams(level);
    }

    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        data = new ArrayList<>();
        this.privateKey = (BignPrivateKey) privateKey;
        int level = this.privateKey.getBytes().length * 4;
        if ((level == 128) || (level == 192) || (level == 256))
            params = new BignParams(level);
    }


    protected void engineUpdate(byte b) {
        data.add(b);
    }

    protected void engineUpdate(byte[] b, int off, int len) {
        for (int i = off; i < len; i++) {
            data.add(b[i]);
        }
    }

    protected byte[] engineSign() throws SignatureException {
        byte[] sig = new byte[3 * (int)params.l / 8];
        byte[] oid_der = new byte[11];
        byte[] hash;
        byte[] byte_data = Util.bytes(data);
        try {
            MessageDigest md = MessageDigest.getInstance(getHashAlgorithm());
            hash = md.digest(byte_data);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException("Hash algorithm is not supported.");
        }
        LongByReference pointer = new LongByReference(128);
        if (bee2.bignOidToDER(oid_der, pointer, getHashOid()) != 0)
            return null;
        if (bee2.bignSign(sig, params, oid_der, 11, hash, privateKey.getBytes(), rng, brng_state) != 0)
            return null;

        return sig;
    }

    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        byte[] oid_der = new byte[11];
        byte[] hash;
        byte[] byte_data = Util.bytes(data);
        try {
            MessageDigest md = MessageDigest.getInstance(getHashAlgorithm());
            hash = md.digest(byte_data);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException("Hash algorithm is not supported.");
        }
        LongByReference pointer = new LongByReference(params.l);
        if (bee2.bignOidToDER(oid_der, pointer, getHashOid()) != 0)
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
