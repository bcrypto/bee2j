package by.bcrypto.bee2j.provider;

import java.security.PrivateKey;
import by.bcrypto.bee2j.BignParams;

public class BignPrivateKey extends BignKey implements PrivateKey{
    public byte[] privKey;
    public BignPrivateKey() {
        super();    //To change body of overridden methods use File | Settings | File Templates.
    }

    public BignPrivateKey(byte[] bytes) {
        super(bytes);
        privKey = bytes;
    }

    @Override
    public void setBytes(byte[] bytes) {
        super.setBytes(bytes);
        bignParams = new BignParams(bytes.length * 4);
    }

    @Override
    public byte[] getBytes() {
        return super.getBytes();
    }
    @Override
    public byte[] getEncoded()
    {
        return privKey;
    }

    @Override
    public String getFormat() {
        return "plain";
    }
}
