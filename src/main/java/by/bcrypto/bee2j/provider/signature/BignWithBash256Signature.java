package by.bcrypto.bee2j.provider.signature;

import by.bcrypto.bee2j.constants.*;

public class BignWithBash256Signature extends BignSignature {

    public String getHashAlgorithm() {
        return JceNameConstants.Bash256;
    }

    public String getHashOid() {
        return OidConstants.Bash256;
    }
}