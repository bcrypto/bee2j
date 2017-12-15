package by.bcrypto.bee2j.provider;

import java.security.*;
import java.util.ArrayList;
import by.bcrypto.bee2j.Bee2Library;
import by.bcrypto.bee2j.BignParams;
import com.sun.jna.ptr.IntByReference;

public class BignSignature extends SignatureSpi{

    int state;
    PublicKey publicKey;
    PrivateKey privateKey;
    ArrayList<Byte> data = new ArrayList<Byte>();
    BignParams params;
    Bee2Library bee2 = Bee2Library.INSTANCE;
    private Bee2Library.IRngFunction _rng = new Bee2Library.BrngFuncForPK();
    byte[] brng_state = new byte[1024];
    //0 - sign
    //1 - verify

    public Bee2Library.IRngFunction getRng()
    {
        return _rng;
    }

    public void setRng(Bee2Library.IRngFunction rng)
    {
        _rng = rng;
    }
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        data  = new ArrayList<Byte>();
        this.state = 1;
        this.publicKey = publicKey;
        if(publicKey.getEncoded().length*2==128) {
            params = new BignParams(128);
            return;
        }
        if(publicKey.getEncoded().length*2==192)
        {
            params = new BignParams(192);
            return;
        }
        if(publicKey.getEncoded().length*2==256)
        {
            params = new BignParams(256);
            return;
        }
    }

    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        data  = new ArrayList<Byte>();
        this.state = 0;
        this.privateKey = privateKey;
        if(privateKey.getEncoded().length*4==128) {
            params = new BignParams(128);
            return;
        }
        if(privateKey.getEncoded().length*4==192)
        {
            params = new BignParams(192);
            return;
        }
        if(privateKey.getEncoded().length*4==256)
        {
            params = new BignParams(256);
            return;
        }
    }

    protected void engineUpdate(byte b) throws SignatureException {
        data.add(b);
    }

    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        for (int i=off; i<len; i++){
            data.add(b[i]);
        }
    }

    protected byte[] engineSign() throws SignatureException {
        byte[] sig = new byte[3*params.l/8];
        byte[] oid_der= new byte[128];
        byte[] hash = new byte[32];
        byte[] byte_data = Util.bytes(data);
        bee2.beltHash(hash,byte_data,byte_data.length);
        IntByReference pointer = new IntByReference(128);
        if(bee2.bignOidToDER(oid_der, pointer, "1.2.112.0.2.0.34.101.31.81")!=0)
            return  null;
        if(bee2.bignSign(sig,params,oid_der,11,hash,privateKey.getEncoded(),_rng,brng_state)!=0)
            return null;
        return sig;
    }

    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        byte[] oid_der= new byte[11];
        byte[] hash = new byte[32];
        byte[] byte_data = Util.bytes(data);

       bee2.beltHash(hash,byte_data,byte_data.length);
        IntByReference pointer = new IntByReference(params.l);
        if(bee2.bignOidToDER(oid_der, pointer, "1.2.112.0.2.0.34.101.31.81")!=0)
            return  false;
        if(bee2.bignVerify(params, oid_der, 11,hash, sigBytes, publicKey.getEncoded())==0)
            return true;
        return false;
    }

    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {

    }

    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }
}
