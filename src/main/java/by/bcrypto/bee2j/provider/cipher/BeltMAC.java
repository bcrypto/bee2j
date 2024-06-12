package by.bcrypto.bee2j.provider.cipher;

public final class BeltMAC extends BeltCipher {
    public BeltMAC() {
        super("MAC");
    }
    @Override
    protected byte[] initState(byte[] key, byte[] iv) {
        byte[] state = new byte[(int)bee2.beltMAC_keep()];
        bee2.beltMACStart(state, key, key.length);
        return state;
    }
    @Override
    protected byte[] updateState(byte[] data, int op, byte[] state) {
        byte[] result = data.clone();
        bee2.beltMACStepA(result, result.length, state);
        return null;
    }
    @Override
    protected byte[] finishState(byte[] state) {
        byte[] mac = new byte[8];
        bee2.beltMACStepG(mac, state);
        return mac;
    }
}