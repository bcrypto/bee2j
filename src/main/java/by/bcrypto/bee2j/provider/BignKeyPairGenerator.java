package by.bcrypto.bee2j.provider;

import by.bcrypto.bee2j.Bee2Library;
import by.bcrypto.bee2j.BignParams;
import java.security.*;

public class BignKeyPairGenerator extends KeyPairGeneratorSpi{

    private static final Bee2Library bee2 = Bee2Library.INSTANCE;
    private int level;
    private SecureRandom secureRandom;

    public BignKeyPairGenerator()
    {
        level = 128;
        secureRandom = new BrngSecureRandom();
    }

    public void initialize(int level, SecureRandom random) {
        this.level = level;
        this.secureRandom = random;
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] byte_privateKey = new byte[level/4];
        byte[] byte_publicKey = new byte[level/2];
        BignParams params = new BignParams(level);
        byte[] brng_state = new byte[1024];
        BrngSecureRandom rng = (BrngSecureRandom) secureRandom;
        if (bee2.bignKeypairGen(byte_privateKey, byte_publicKey, params, rng.getRng(), brng_state) != 0)
            return null;
        PublicKey publicKey = new BignPublicKey(byte_publicKey);
        PrivateKey privateKey = new BignPrivateKey(byte_privateKey);

        return new KeyPair(publicKey, privateKey);
    }
}
