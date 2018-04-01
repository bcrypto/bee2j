package by.bcrypto.bee2j.provider.messageDigest;

import java.security.MessageDigestSpi;
import java.util.ArrayList;
import by.bcrypto.bee2j.Bee2Library;
import by.bcrypto.bee2j.provider.*;

public class BeltMessageDigest extends MessageDigestSpi implements Cloneable {

    private ArrayList<Byte> data = new ArrayList<Byte>();

    protected void engineUpdate(byte input) {
        data.add(input);
    }

    protected void engineUpdate(byte[] input, int offset, int len) {
        for (int i = offset; i < offset + len; i++)
            data.add(input[i]);
    }

    protected byte[] engineDigest() {

        byte[] bytes= Util.bytes(data);

        Bee2Library bee2 = Bee2Library.INSTANCE;
        byte[] hash = new byte[32];

        int res = bee2.beltHash(hash, bytes, bytes.length);
        if(res!=0)
            throw new RuntimeException("BeltHash hash was broken");
        return hash;
    }

    protected void engineReset() {
        data.clear();
    }

    protected int engineGetDigestLength() {
        return 32;
    }
}
