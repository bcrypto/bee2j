package by.bcrypto.bee2j.provider.cipher;

public final class BeltCFB extends BeltCipher {
    public BeltCFB() {
        super("CFB");
    }
    @Override
    protected byte[] initState(byte[] key, byte[] iv) {
        byte[] state = new byte[(int)bee2.beltCFB_keep()];
        bee2.beltCFBStart(state, key, key.length, iv);
        return state;
    }
    @Override
    protected byte[] updateState(byte[] data, int op, byte[] state) {
        byte[] result = data.clone();
        if(op == 1)
            bee2.beltCFBStepE(result, result.length, state);
        else if (op == 2)
            bee2.beltCFBStepD(result, result.length, state);
        return result;
    }
}