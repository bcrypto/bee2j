package by.bcrypto.bee2j.provider.signature;

import by.bcrypto.bee2j.constants.*;

public class BignWithBash512Signature extends BignSignature {

    public String getHashAlgorithm() {
        return JceNameConstants.Bash512;
    }

    public String getHashOid() {
        return OidConstants.Bash512;
    }
}