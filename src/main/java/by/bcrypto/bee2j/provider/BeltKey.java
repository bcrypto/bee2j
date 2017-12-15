package by.bcrypto.bee2j.provider;

import javax.crypto.SecretKey;

public class BeltKey implements SecretKey {

    byte[] secretKey;

    public BeltKey(byte[] secretKey)
    {
        this.secretKey = secretKey;
    }
    public String getAlgorithm() {
        return "Belt";
    }

    public String getFormat() {
        return "Plain";
    }

    public byte[] getEncoded() {
        return secretKey;
    }

}
