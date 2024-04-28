package by.bcrypto.bee2j;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Base64;

import by.bcrypto.bee2j.provider.Util;
import junit.framework.TestCase;

public class Bee2ImportTest extends TestCase{

    public void testBytesFromAsn1PublicKey() throws UnsupportedEncodingException {
        String asn1 = "MH0wGAYKKnAAAgAiZS0CAQYKKnAAAgAiZS0DAgNhAN95y+mBMi1j"
        + "MUUwnRQWCrZHDX56RC1jXhbZxflc2vouCUKiYxpR3Tn87tb8e6XwTgLGH8qr+nTd" 
        + "HvDmPYl99+xVW+PvUNXhCrLm6iRMUCAI239T4Jm+U1NCdYwpTjw7Dw";
        byte[] encodedKey = Base64.getDecoder().decode(new String(asn1).getBytes("UTF-8"));
        byte[] key = Util.getBytesFromAsn1PublicKey(encodedKey);
        String pk = "A2EA33nL6YEyLWMxRTCdFBYKtkcNfnpELWNeFtnF+Vza+i4JQ"
        + "qJjGlHdOfzu1vx7pfBOAsYfyqv6dN0e8OY9iX337FVb4+9Q1eEKsubqJExQIAjbf1"
        + "Pgmb5TU0J1jClOPDsP";
        byte[] decodedKey = Base64.getDecoder().decode(new String(pk).getBytes("UTF-8"));
        byte[] value = Arrays.copyOfRange(decodedKey, 3, decodedKey.length);
        assertTrue(Arrays.equals(value, key));
        assertEquals(Util.bytesToHex(value), Util.bytesToHex(key));
    }

    public void testBytesFromAsn1PublicKey2() throws IOException {
        String asn1 = "MH0wGAYKKnAAAgAiZS0CAQYKKnAAAgAiZS0DAgNhAN95y+mBMi1j"
        + "MUUwnRQWCrZHDX56RC1jXhbZxflc2vouCUKiYxpR3Tn87tb8e6XwTgLGH8qr+nTd" 
        + "HvDmPYl99+xVW+PvUNXhCrLm6iRMUCAI239T4Jm+U1NCdYwpTjw7Dw";
        byte[] encodedKey = Base64.getDecoder().decode(new String(asn1).getBytes("UTF-8"));
        byte[] key = Util.getBytesFromAsn1PublicKey2(encodedKey);
        String pk = "A2EA33nL6YEyLWMxRTCdFBYKtkcNfnpELWNeFtnF+Vza+i4JQ"
        + "qJjGlHdOfzu1vx7pfBOAsYfyqv6dN0e8OY9iX337FVb4+9Q1eEKsubqJExQIAjbf1"
        + "Pgmb5TU0J1jClOPDsP";
        byte[] decodedKey = Base64.getDecoder().decode(new String(pk).getBytes("UTF-8"));
        byte[] value = Arrays.copyOfRange(decodedKey, 3, decodedKey.length);
        assertEquals(Util.bytesToHex(value), Util.bytesToHex(key));
        assertTrue(Arrays.equals(value, key));
    }
}
