package by.bcrypto.bee2j.provider;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DLSequence;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;

import by.bcrypto.bee2j.Bee2Library;
import by.bcrypto.bee2j.DerAnchor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class Util {

    static public byte[] bytes(ArrayList<Byte> data) {
        byte[] bytes = new byte[data.size()];
        for (int i = 0; i < data.size(); i++)
            bytes[i] = data.get(i);

        return bytes;
    }

    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
    public static String bytesToHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    static public byte[] getBytesFromAsn1PublicKey(byte[] asn1encodedByte) {
        byte[] bytes = null;
        try (ASN1InputStream input = new ASN1InputStream(asn1encodedByte)) {
            ASN1Primitive encodedKey = input.readObject();
            if (encodedKey instanceof DLSequence)
            {
                DLSequence dlSequence = (DLSequence) encodedKey;

                DERBitString derBitString = (DERBitString) dlSequence.getObjectAt(1);
                bytes = derBitString.getOctets();
            }
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }

        return bytes;
    }

    static public byte[] getBytesFromAsn1PublicKey2(byte[] asn1encodedByte) throws IOException {
        byte[] bytes = null;
        Bee2Library bee2 = Bee2Library.INSTANCE;
        DerAnchor pki = new DerAnchor();
        DerAnchor algid = new DerAnchor();
        int len = asn1encodedByte.length;
        Pointer ptr = new Memory(len);
        Pointer fptr;
        IntByReference keylen = new IntByReference(0);
        IntByReference oidlen = new IntByReference(0);
        System.out.println(ptr);
        ptr.write(0, asn1encodedByte, 0, len);
        System.out.println(ptr);
        int t = 0;
        t = bee2.derTSEQDecStart(pki, ptr, len, 0x30);
        System.out.println(ptr);
        if (t < 0)
            throw new IOException("DER encoding problem.");
        len -= t;
        fptr = ptr.share(t);
        System.out.println(fptr);
        t = bee2.derTSEQDecStart(algid, fptr, len, 0x30);
        if (t < 0)
            throw new IOException("DER encoding problem.");
        len -= t;
        fptr = fptr.share(t);
        System.out.println(fptr);
        t = bee2.derOIDDec(bytes, oidlen, fptr, len);
        System.out.println(oidlen);
        if (t < 0)
            throw new IOException("DER encoding problem.");
        len -= t;
        fptr = fptr.share(t);
        System.out.println(fptr);
        t = bee2.derOIDDec(bytes, oidlen, fptr, len);
        System.out.println(oidlen);
        if (t < 0)
            throw new IOException("DER encoding problem.");
        len -= t;
        fptr = fptr.share(t);
        System.out.println(fptr);
        t = bee2.derTSEQDecStop(fptr, algid);
        if (t < 0)
            throw new IOException("DER encoding problem.");
        len -= t;
        fptr = fptr.share(t);
        System.out.println(fptr);
        t = bee2.derTBITDec(bytes, keylen, fptr, len, 0x03);
        System.out.println(keylen);
        if (t < 0)
            throw new IOException("DER encoding problem.");
        bytes = new byte[keylen.getValue()/8];
        t = bee2.derTBITDec(bytes, keylen, fptr, len, 0x03);
        len -= t;
        fptr = fptr.share(t);
        System.out.println(fptr);
        t = bee2.derTSEQDecStop(fptr, pki);
        if (t < 0)
            throw new IOException("DER encoding problem.");

        System.out.println(t);
        return bytes;
    }
}
