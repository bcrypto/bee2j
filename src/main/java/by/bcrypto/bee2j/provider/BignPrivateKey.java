package by.bcrypto.bee2j.provider;

import java.security.PrivateKey;
import by.bcrypto.bee2j.BignParams;

public class BignPrivateKey extends BignKey implements PrivateKey{
    public BignPrivateKey(byte[] bytes) {
        super(bytes, new BignParams(bytes.length * 4));
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    @Override
    public String getFormat() {
        return null;
    }
}
