package by.bcrypto.bee2j.provider;

import by.bcrypto.bee2j.Bee2Library;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class BignKeyFactory extends KeyFactorySpi{

    private final Bee2Library bee2 = Bee2Library.INSTANCE;

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        return null;
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {

        BignPrivateKeySpec bignPrivateKeySpec = (BignPrivateKeySpec) keySpec;

        if (bignPrivateKeySpec == null)
            throw new InvalidKeySpecException("Provided KeySpec instance is not an instance of "+ BignPrivateKeySpec.class.getSimpleName());

        byte[] bytePrivateKey = new byte[32];
        var code = bee2.bpkiPrivkeyUnwrap(
                bytePrivateKey,
                null,
                bignPrivateKeySpec.container,
                bignPrivateKeySpec.container.length,
                bignPrivateKeySpec.password.getBytes(),
                bignPrivateKeySpec.password.getBytes().length);
        if (code != 0)
        {
            System.out.println( "Unwrap private key error. Code " + code);
            throw new InvalidKeySpecException("Provided KeySpec is invalid. Code " + code);
        }

        return new BignPrivateKey(bytePrivateKey);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        return null;
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        return null;
    }
}
