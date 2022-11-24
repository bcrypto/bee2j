package by.bcrypto.bee2j.provider;

import by.bcrypto.bee2j.BignParams;
import java.math.BigInteger;
import java.security.*;

public abstract class BignKey implements Key{
    protected byte[] bytes;
    protected BignParams bignParams;

    protected BignKey(byte[] bytes, BignParams bignParams) {
        super();
        this.bytes = bytes;
        this.bignParams = bignParams;
    }

    public byte[] getBytes(){
        return bytes;
    }

    public String getAlgorithm() {
        return switch (bignParams.l) {
            case 128 -> "1.2.112.0.2.0.34.101.45.2.1";
            case 192 -> "1.2.112.0.2.0.34.101.45.2.2";
            case 256 -> "1.2.112.0.2.0.34.101.45.2.3";
            default -> throw new IllegalArgumentException("Level " + bignParams.l + " is invalid");
        };
    }

    @Override
    public boolean equals(Object obj) {
        return new BigInteger(bytes).equals(new BigInteger(((BignKey)obj).bytes));
    }
}

