package by.bcrypto.bee2j.provider;

import by.bcrypto.bee2j.BignParams;

import java.security.PublicKey;

public class BignPublicKey extends BignKey implements PublicKey {
    public BignPublicKey(byte[] bytes) {
        super(bytes, new BignParams(bytes.length * 2));
    }

    @Override
    public byte[] getEncoded() {
        return bytes;
    }

    @Override
    public String getFormat() {
        return null;
    }
}
