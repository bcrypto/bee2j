package by.bcrypto.bee2j.provider.signature;

import by.bcrypto.bee2j.constants.*;

public class BignWithBash384Signature extends BignSignature {

    public String getHashAlgorithm() {
        return JceNameConstants.Bash384;
    }

    public String getHashOid() {
        return OidConstants.Bash384;
    }
}