package by.bcrypto.bee2j.der;

import java.io.IOException;
import java.util.ArrayList;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;

import by.bcrypto.bee2j.Bee2Library;

public class DerSequence extends DerValue {
    public DerSequence(byte[] der, byte tag, long length, long offset) {
        super(der, tag, length, offset);
    }

    public DerSequence(byte[] der) {
        super(der);
    }

    public DerSequence(DerValue der) {
        super(der);
    }

    public ArrayList<DerValue> getSequence() throws IOException {
        if (this.getTag() != tag_Sequence) {
            throw new IOException("Sequence tag error");
        } 
        Bee2Library bee2 = Bee2Library.INSTANCE;
        DerAnchor seq = new DerAnchor();
        long len = this.size;
        long t = bee2.derTSEQDecStart(seq, this.ptr, len, tag_Sequence);
        if (t < 0)
            throw new IOException("DER encoding problem.");
        len -= t;
        long shift = t;
        ArrayList<DerValue> items = new ArrayList<DerValue>();
        while (len > 0) {
            if (t < 0)
                throw new IOException("DER encoding problem.");
            Pointer fptr = ptr.share(shift);
            IntByReference tagRef = new IntByReference(0);
            LongByReference lenRef = new LongByReference(0);
            t = bee2.derTLDec(tagRef, lenRef, fptr, len);
            if (t < 0)
                throw new IOException("DER length encoding problem.");
            int itemLen = (int)(t + lenRef.getValue());
            byte tag = (byte) tagRef.getValue();
            byte[] value = fptr.getByteArray(0, itemLen);
            items.add(DerValue.unmarshal(value, tag, lenRef.getValue(), t));
            len -= itemLen;
            shift += itemLen;
        }
        Pointer end = ptr.share(shift);
        t = bee2.derTSEQDecStop(end, seq);
        if (t < 0)
            throw new IOException("DER encoding problem.");
        return items;
    }
}
