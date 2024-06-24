package by.bcrypto.bee2j.provider.cipher;

public final class BeltCBC extends BeltCipher {
    public BeltCBC() {
        super("CBC");
    }
    @Override
    protected byte[] initState(byte[] key, byte[] iv) {
        byte[] state = new byte[(int)bee2.beltCBC_keep()];
        bee2.beltCBCStart(state, key, key.length, iv);
        return state;
    }
    @Override
    protected byte[] updateState(byte[] data, int op, byte[] state) {
        byte[] result = data.clone();
        if(op == 1)
            bee2.beltCBCStepE(result, result.length, state);
        else if (op == 2)
            bee2.beltCBCStepD(result, result.length, state);
        return result;
    }
}