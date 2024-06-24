package by.bcrypto.bee2j.der;

import java.io.IOException;
import com.sun.jna.ptr.LongByReference;

import by.bcrypto.bee2j.Bee2Library;

public class DerBitString extends DerValue {

    private byte[] bits;
    private int bitLength;

    public DerBitString(byte[] der, byte tag, long length, long offset) {
        super(der, tag, length, offset);
    }

    public DerBitString(byte[] der) {
        super(der);
    }

    public DerBitString(DerValue der) {
        super(der);
    }

    private void parse() throws IOException {
        if (this.getTag() != tag_BitString) {
            throw new IOException("Sequence tag error");
        } 
        Bee2Library bee2 = Bee2Library.INSTANCE;
        byte[] bytes = null;
        int t;
        LongByReference keyLen = new LongByReference(0);
        t = bee2.derTBITDec(bytes, keyLen, this.ptr, this.size, tag_BitString);
        if (t < 0)
            throw new IOException("DER encoding problem.");
        bytes = new byte[(int)(keyLen.getValue() + 7) / 8];
        t = bee2.derTBITDec(bytes, keyLen, this.ptr, this.size, tag_BitString);
        if (t < 0)
            throw new IOException("DER encoding problem.");
        this.bitLength = (int) keyLen.getValue();
        this.bits = bytes;
    }

    public byte[] getBitString() throws IOException {
        if (this.bits == null) {
            parse();
        } 
        return this.bits;
    }

    public int getBitLength() throws IOException {
        if (this.bits == null) {
            parse();
        } 
        return this.bitLength;
    }
}
