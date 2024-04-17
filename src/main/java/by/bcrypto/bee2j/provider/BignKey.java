package by.bcrypto.bee2j.provider;

import by.bcrypto.bee2j.BignParams;
import by.bcrypto.bee2j.constants.JceNameConstants;

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

    public BignParams getParams(){
        return bignParams;
    }

    public String getAlgorithm() {
        return JceNameConstants.BignPubKey;
    }

    @Override
    public boolean equals(Object obj) {
        return new BigInteger(bytes).equals(new BigInteger(((BignKey)obj).bytes));
    }
}

