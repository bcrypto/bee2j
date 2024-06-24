package by.bcrypto.bee2j.provider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import by.bcrypto.bee2j.der.DerBitString;
import by.bcrypto.bee2j.der.DerSequence;
import by.bcrypto.bee2j.der.DerValue;

public class Util {

    static public byte[] bytes(ArrayList<Byte> data) {
        byte[] bytes = new byte[data.size()];
        for (int i = 0; i < data.size(); i++)
            bytes[i] = data.get(i);

        return bytes;
    }

    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
    public static String bytesToHex(byte[] bytes) {
        if(bytes == null)
            return "";
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    static public byte[] getBytesFromAsn1PublicKey(byte[] asn1encodedByte) {
        byte[] key = null;
        DerSequence der = new DerSequence(asn1encodedByte);
        try {
            ArrayList<DerValue> items = der.getSequence();
            DerBitString derKey = (DerBitString) items.get(1);
            key = derKey.getBitString();
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
        return key;
    }
}
