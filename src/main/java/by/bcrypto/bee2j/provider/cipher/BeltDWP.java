package by.bcrypto.bee2j.provider.cipher;

public final class BeltDWP extends BeltCipher {
    public BeltDWP() {
        super("DWP");
    }
    @Override
    protected byte[] initState(byte[] key, byte[] iv) {
        byte[] state = new byte[(int)bee2.beltDWP_keep()];
        bee2.beltDWPStart(state, key, key.length, iv);
        return state;
    }
    @Override
    protected byte[] updateState(byte[] data, int op, byte[] state) {
        byte[] result = data.clone();
        if(op == 1) {
            bee2.beltDWPStepE(result, result.length, state);
            bee2.beltDWPStepA(result, result.length, state);
        } else if (op == 2) {
            bee2.beltDWPStepA(result, result.length, state);
            bee2.beltDWPStepD(result, result.length, state);
        }   
        return result;
    }
    @Override
    protected byte[] finishState(byte[] state) {
        byte[] mac = new byte[8];
        bee2.beltDWPStepG(mac, state);
        return mac;
    }
    @Override
    protected void updateAAD(byte[] data, byte[] state) {
        bee2.beltDWPStepI(data, data.length, state);
    }
}