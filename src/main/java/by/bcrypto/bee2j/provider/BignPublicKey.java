package by.bcrypto.bee2j.provider;

import by.bcrypto.bee2j.BignParams;
import java.security.PublicKey;

public class BignPublicKey extends BignKey implements PublicKey {
    byte[] publicKey;
    @Override
    public void setBytes(byte[] bytes) {
        super.setBytes(bytes);
        bignParams = new BignParams(bytes.length * 2);
    }

    public BignPublicKey() {
        super();  }

    public BignPublicKey(byte[] bytes) {
        super(bytes);
        publicKey = bytes;
    }
    @Override
    public byte[] getEncoded()
    {
        return publicKey;
    }

    @Override
    public String getFormat() {
        return "plain";
    }
}
