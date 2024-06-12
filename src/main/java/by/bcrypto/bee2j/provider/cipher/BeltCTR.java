package by.bcrypto.bee2j.provider.cipher;

public final class BeltCTR extends BeltCipher {
    public BeltCTR() {
        super("CTR");
    }
    @Override
    protected byte[] initState(byte[] key, byte[] iv) {
        byte[] state = new byte[(int)bee2.beltCTR_keep()];
        bee2.beltCTRStart(state, key, key.length, iv);
        return state;
    }
    @Override
    protected byte[] updateState(byte[] data, int op, byte[] state) {
        byte[] result = data.clone();
        if(op == 1)
            bee2.beltCTRStepE(result, result.length, state);
        else if (op == 2)
            bee2.beltCTRStepE(result, result.length, state);
        return result;
    }
}