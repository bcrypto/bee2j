package by.bcrypto.bee2j.provider;

import java.security.spec.KeySpec;

public class BignPrivateKeySpec implements KeySpec {

    public byte[] container;
    public String password;

    public BignPrivateKeySpec(byte[] container, String password)
    {
        this.container = container;
        this.password = password;
    }
}
