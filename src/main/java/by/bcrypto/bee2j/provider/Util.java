package by.bcrypto.bee2j.provider;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DLSequence;

import java.io.IOException;
import java.util.ArrayList;

public class Util {

    static public byte[] bytes(ArrayList<Byte> data) {
        byte[] bytes = new byte[data.size()];
        for (int i = 0; i < data.size(); i++)
            bytes[i] = data.get(i);

        return bytes;
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
}
