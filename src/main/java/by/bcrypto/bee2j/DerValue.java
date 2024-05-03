package by.bcrypto.bee2j;

import java.io.IOException;
import java.util.ArrayList;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;

public class DerValue {
    
    protected Pointer ptr = null;
    protected long size = 0;
    protected byte tag = 0;
    protected long length = 0;
    protected long offset = 0;
    private boolean initialized = false;

    public static final byte tag_Boolean = 1;
    public static final byte tag_Integer = 2;
    public static final byte tag_BitString = 3;
    public static final byte tag_OctetString = 4;
    public static final byte tag_Null = 5;
    public static final byte tag_ObjectId = 6;
    public static final byte tag_Enumerated = 10;
    public static final byte tag_UTF8String = 12;
    public static final byte tag_PrintableString = 19;
    public static final byte tag_T61String = 20;
    public static final byte tag_IA5String = 22;
    public static final byte tag_UtcTime = 23;
    public static final byte tag_GeneralizedTime = 24;
    public static final byte tag_GeneralString = 27;
    public static final byte tag_UniversalString = 28;
    public static final byte tag_BMPString = 30;
    public static final byte tag_Sequence = 48;
    public static final byte tag_SequenceOf = 48;
    public static final byte tag_Set = 49;
    public static final byte tag_SetOf = 49;

    public DerValue(byte[] der) {
        this.size = der.length;
        this.ptr = new Memory(this.size);
        System.out.println("Alloc new " + this.ptr);
        this.ptr.write(0, der, 0, (int) this.size);
    }

    DerValue(byte[] der, byte tag, long length, long offset) {
        this.size = der.length;
        this.ptr = new Memory(this.size);
        System.out.println("Alloc new " + this.ptr);
        this.ptr.write(0, der, 0, (int)this.size);
        this.tag = tag;
        this.length = length;
        this.offset = offset;
        this.initialized = true;
    }

    private void init() throws IOException {
        if ((!this.initialized) && (this.ptr != null)) {
            Bee2Library bee2 = Bee2Library.INSTANCE;
            IntByReference tagref = new IntByReference(0);
            LongByReference lenref = new LongByReference(0);
            this.offset = bee2.derTLDec(tagref, lenref, this.ptr, this.size);
            if (offset < 0)
                throw new IOException("DER length encoding problem.");
            this.tag = (byte) tagref.getValue();
            this.length = lenref.getValue();
            this.initialized = true;
        }
    }

    public long getLength() throws IOException {
        if (!this.initialized)
            init();
        return this.length;
    }

    public byte getTag() throws IOException {
        if (!this.initialized)
            init();
        return this.tag;
    }

    public String toString(){
        return "[DerValue, tag=" + this.tag + ", length=" + this.length + "]";
    }

    public ArrayList<DerValue> getSequence() throws IOException {
        if (this.getTag() != tag_Sequence) {
            throw new IOException("Sequence tag error");
        } 
        Bee2Library bee2 = Bee2Library.INSTANCE;
        DerAnchor seq = new DerAnchor();
        long len = this.size;
        long t = 0;
        t = bee2.derTSEQDecStart(seq, this.ptr, len, 0x30);
        if (t < 0)
            throw new IOException("DER encoding problem.");
        len -= t;
        long shift = t;
        ArrayList<DerValue> items = new ArrayList<DerValue>();
        while (len > 0) {
            if (t < 0)
                throw new IOException("DER encoding problem.");
            Pointer fptr = ptr.share(shift);
            IntByReference tagref = new IntByReference(0);
            LongByReference lenref = new LongByReference(0);
            t = bee2.derTLDec(tagref, lenref, fptr, len);
            if (t < 0)
                throw new IOException("DER length encoding problem.");
            int itemLen = (int)(t + lenref.getValue());
            byte[] value = fptr.getByteArray(0, itemLen);
            items.add(new DerValue(
                value, (byte) tagref.getValue(), lenref.getValue(), t));
            len -= itemLen;
            shift += itemLen;
        }
        Pointer end = ptr.share(shift);
        t = bee2.derTSEQDecStop(end, seq);
        if (t < 0)
            throw new IOException("DER encoding problem.");
        return items;
    }

    public byte[] getBitString() throws IOException {
        if (this.getTag() != tag_BitString) {
            throw new IOException("Sequence tag error");
        } 
        Bee2Library bee2 = Bee2Library.INSTANCE;
        byte[] bytes = null;
        int t;
        LongByReference keylen = new LongByReference(0);
        t = bee2.derTBITDec(bytes, keylen, this.ptr, this.size, 0x03);
        if (t < 0)
            throw new IOException("DER encoding problem.");
        bytes = new byte[(int)(keylen.getValue() + 7) / 8];
        t = bee2.derTBITDec(bytes, keylen, this.ptr, this.size, 0x03);
        if (t < 0)
            throw new IOException("DER encoding problem.");
        return bytes;
    }

}
