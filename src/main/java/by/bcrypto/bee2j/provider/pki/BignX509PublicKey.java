package by.bcrypto.bee2j.provider.pki;

import by.bcrypto.bee2j.provider.BignPublicKey;

public class BignX509PublicKey extends BignPublicKey {

    private final byte[] encodedBytes;

    public BignX509PublicKey(byte[] decodedBytes, byte[] encodedBytes) {
        super(decodedBytes);
        this.encodedBytes = encodedBytes;
    }

    @Override
    public byte[] getEncoded() {
        return encodedBytes;
    }
}
