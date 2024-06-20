package by.bcrypto.bee2j.der;

import java.io.IOException;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;

import by.bcrypto.bee2j.Bee2Library;

public class DerValue {
    
    private boolean initialized = false;
    protected Pointer ptr;
    protected long size;
    protected byte tag;
    protected long length;
    protected long offset;

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

    public DerValue(byte[] der, byte tag, long length, long offset) {
        this.size = der.length;
        this.ptr = new Memory(this.size);
        this.ptr.write(0, der, 0, (int)this.size);
        this.tag = tag;
        this.length = length;
        this.offset = offset;
        this.initialized = true;
    }

    public DerValue(byte[] der) {
        this.size = der.length;
        this.ptr = new Memory(this.size);
        this.ptr.write(0, der, 0, (int) this.size);
    }

    public DerValue(DerValue v) {
        this.size = v.size;
        this.ptr = new Memory(this.size);
        this.ptr.write(0, v.ptr.getByteArray(0, (int) v.size), 
            0, (int) this.size);
        if(v.initialized) {
            this.tag = v.tag;
            this.length = v.length;
            this.offset = v.offset;
            this.initialized = true;            
        }
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

    public static DerValue unmarshal(
        byte[] der, byte tag, long length, long offset
    ) {
        switch (tag) {
            case tag_BitString:
                return (DerValue) new DerBitString(der, tag, length, offset);
            case tag_Sequence:
                return (DerValue) new DerSequence(der, tag, length, offset);
            default:
                return new DerValue(der, tag, length, offset);
        }
    }

    public DerValue unmarshal() {
        return unmarshal(this.ptr.getByteArray(0, (int) this.size), 
            this.tag, this.length, this.offset);
    }
}
