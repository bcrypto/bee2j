package by.bcrypto.bee2j.provider;

import by.bcrypto.bee2j.constants.JceNameConstants;
import by.bcrypto.bee2j.constants.OidConstants;
import by.bcrypto.bee2j.provider.messageDigest.Bash256MessageDigest;
import by.bcrypto.bee2j.provider.messageDigest.Bash384MessageDigest;
import by.bcrypto.bee2j.provider.messageDigest.Bash512MessageDigest;
import by.bcrypto.bee2j.provider.messageDigest.BeltMessageDigest;
import by.bcrypto.bee2j.provider.pki.BignCertificateFactory;
import by.bcrypto.bee2j.provider.signature.BignWithBash256Signature;
import by.bcrypto.bee2j.provider.signature.BignWithBash384Signature;
import by.bcrypto.bee2j.provider.signature.BignWithBash512Signature;
import by.bcrypto.bee2j.provider.signature.BignWithBeltSignature;

import java.security.*;

public final class Bee2SecurityProvider extends Provider {
    public Bee2SecurityProvider() {
        super(JceNameConstants.ProviderName, "1.0", "Bee2 Security Provider v1.0");
        put("MessageDigest." + JceNameConstants.Belt, BeltMessageDigest.class.getCanonicalName());
        put("MessageDigest." + JceNameConstants.Bash256, Bash256MessageDigest.class.getCanonicalName());
        put("MessageDigest." + JceNameConstants.Bash384, Bash384MessageDigest.class.getCanonicalName());
        put("MessageDigest." + JceNameConstants.Bash512, Bash512MessageDigest.class.getCanonicalName());

        put("Signature." + JceNameConstants.BignWithBelt, BignWithBeltSignature.class.getCanonicalName());
        put("Signature." + JceNameConstants.BignWithBash256, BignWithBash256Signature.class.getCanonicalName());
        put("Signature." + JceNameConstants.BignWithBash384, BignWithBash384Signature.class.getCanonicalName());
        put("Signature." + JceNameConstants.BignWithBash512, BignWithBash512Signature.class.getCanonicalName());

        put("Signature." + OidConstants.BignWithBelt, BignWithBeltSignature.class.getCanonicalName());
        put("Signature." + OidConstants.BignWithBash256, BignWithBash256Signature.class.getCanonicalName());
        put("Signature." + OidConstants.BignWithBash384, BignWithBash384Signature.class.getCanonicalName());
        put("Signature." + OidConstants.BignWithBash512, BignWithBash512Signature.class.getCanonicalName());

        String bignKeyClasses = "by.bcrypto.bee2j.provider.BignPublicKey" +
                "|by.bcrypto.bee2j.provider.BignPrivateKey";
        put("Signature." + JceNameConstants.BignWithBelt + " SupportedKeyClasses", bignKeyClasses);
        put("Signature." + JceNameConstants.BignWithBash256 + " SupportedKeyClasses", bignKeyClasses);
        put("Signature." + JceNameConstants.BignWithBash384 + " SupportedKeyClasses", bignKeyClasses);
        put("Signature." + JceNameConstants.BignWithBash512 + " SupportedKeyClasses", bignKeyClasses);

        put("Cipher.Belt", "by.bcrypto.bee2j.provider.cipher.BeltCipher");
        put("Cipher.BeltECB", "by.bcrypto.bee2j.provider.cipher.BeltECB");
        put("Cipher.BeltCBC", "by.bcrypto.bee2j.provider.cipher.BeltCBC");
        put("Cipher.BeltCFB", "by.bcrypto.bee2j.provider.cipher.BeltCFB");
        put("Cipher.BeltCTR", "by.bcrypto.bee2j.provider.cipher.BeltCTR");
        put("Cipher.BeltMAC", "by.bcrypto.bee2j.provider.cipher.BeltMAC");
        put("Cipher.BeltDWP", "by.bcrypto.bee2j.provider.cipher.BeltDWP");

        put("KeyPairGenerator.Bign", "by.bcrypto.bee2j.provider.BignKeyPairGenerator");
        put("Cipher.Bign", "by.bcrypto.bee2j.provider.by.BignCipherSpi");
        put("SecureRandom.Brng", "by.bcrypto.bee2j.provider.BrngSecureRandom");
        put("Mac.BeltMAC", "by.bcrypto.bee2j.provider.BeltMAC");
        put("KeyFactory.Bign", "by.bcrypto.bee2j.provider.BignKeyFactory");
        put("CertificateFactory.X.509", BignCertificateFactory.class.getCanonicalName());
    }
}
