package by.bcrypto.bee2j.provider.messageDigest;

import by.bcrypto.bee2j.Bee2Library;
import by.bcrypto.bee2j.provider.Util;

import java.security.MessageDigestSpi;
import java.util.ArrayList;

public abstract class BashBaseMessageDigest extends MessageDigestSpi implements Cloneable {

    int _level;
    private ArrayList<Byte> _data = new ArrayList<Byte>();

    BashBaseMessageDigest()
    {
        _level = 128;
    }

    protected void engineUpdate(byte input) {
        _data.add(input);
    }

    protected void engineUpdate(byte[] input, int offset, int len) {
        for (int i = offset; i < offset + len; i++)
            _data.add(input[i]);
    }

    protected byte[] engineDigest() {

        byte[] bytes= Util.bytes(_data);

        Bee2Library bee2 = Bee2Library.INSTANCE;
        byte[] hash = new byte[_level/4];

        int res = bee2.bashHash(hash,_level, bytes, bytes.length);
        if(res!=0)
            throw new RuntimeException("Bash was broken");
        return hash;
    }

    protected void engineReset() {
        _data.clear();
    }

    protected int engineGetDigestLength() {
        return 32;}
}
