package by.bcrypto.bee2j.provider.signature;

import by.bcrypto.bee2j.constants.*;

public class BignWithBeltSignature extends BignSignature {

    public String getHashAlgorithm() {
        return JceNameConstants.Belt;
    }

    public String getHashOid() {
        return OidConstants.Belt;
    }
}
