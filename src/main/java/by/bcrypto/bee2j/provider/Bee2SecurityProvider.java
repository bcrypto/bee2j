package by.bcrypto.bee2j.provider;

import java.security.*;
public final class Bee2SecurityProvider extends Provider{
    public Bee2SecurityProvider()
    {
        super("Bee2", 1.0, "Bee2 Security Provider v1.0");
        put("MessageDigest.BeltHash", "by.bcrypto.bee2j.provider.BeltMessageDigest");
        put("Signature.Bign", "by.bcrypto.bee2j.provider.BignSignature");
        put("KeyPairGenerator.Bign", "by.bcrypto.bee2j.provider.BignKeyPairGenerator");
        put("Cipher.Belt", "by.bcrypto.bee2j.provider.BeltCipher");
        put("Cipher.Bign", "by.bcrypto.bee2j.provider.by.BignCipherSpi");
        //put("KeyGenerator.Belt", BeltKeyGenerator.class.getName());
        put("SecureRandom.Brng","by.bcrypto.bee2j.provider.BrngSecureRandom");
        put("Mac.BeltMAC", "by.bcrypto.bee2j.provider.BeltMAC");
    }
}
