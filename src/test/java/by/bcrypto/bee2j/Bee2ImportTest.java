package by.bcrypto.bee2j;

import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;

import by.bcrypto.bee2j.provider.Bee2SecurityProvider;
import by.bcrypto.bee2j.provider.Util;
import junit.framework.TestCase;

public class Bee2ImportTest extends TestCase{

    public void testBytesFromAsn1PublicKey() throws IOException {
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
        DerValue der = new DerValue(encodedKey);
        assertEquals("[DerValue, tag=0, length=0]", der.toString());
        assertEquals(DerValue.tag_Sequence, der.getTag());
        assertEquals("[DerValue, tag=48, length=125]", der.toString());
        ArrayList<DerValue> items = der.getSequence();
        assertEquals(DerValue.tag_Sequence, items.get(0).getTag());
        assertEquals(DerValue.tag_BitString, items.get(1).getTag());
        byte[] key = items.get(1).getBitString();
        String pk = "A2EA33nL6YEyLWMxRTCdFBYKtkcNfnpELWNeFtnF+Vza+i4JQ"
        + "qJjGlHdOfzu1vx7pfBOAsYfyqv6dN0e8OY9iX337FVb4+9Q1eEKsubqJExQIAjbf1"
        + "Pgmb5TU0J1jClOPDsP";
        byte[] decodedKey = Base64.getDecoder().decode(new String(pk).getBytes("UTF-8"));
        byte[] value = Arrays.copyOfRange(decodedKey, 3, decodedKey.length);
        assertEquals(Util.bytesToHex(value), Util.bytesToHex(key));
        assertTrue(Arrays.equals(value, key));
    }

    static int ERR_OK = 0;

    public void testPrivateKeyWrapUnwrap() {
        //установить провайдер

        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);

        Bee2Library bee2 = Bee2Library.INSTANCE;
        Pointer p = bee2.beltH();

        //src - входные данные из теста A.24 из СТБ 34.101.31

        byte[] src = p.getByteArray(0, 32);
        byte[] srcPad = p.getByteArray(32, 8);
        byte[] pwd = {'z', 'e', 'd'};
        LongByReference key_len = new LongByReference();
        LongByReference epki_len = new LongByReference();
        LongByReference epki_len1 = new LongByReference();
        byte[] key = new byte[32];
        int err;
        // создать контейнер с личным ключом (l = 128)
        err = bee2.bpkiPrivkeyWrap(null, epki_len, src, 32, pwd, 3, srcPad, 10001);
        assertEquals(ERR_OK, err);
        byte[] epki = new byte[(int)epki_len.getValue()];
        err = bee2.bpkiPrivkeyWrap(epki, epki_len1, src, 32, pwd, 3, srcPad, 10001);        assertEquals(err, ERR_OK);
        assertEquals(ERR_OK, err);
        assertEquals(epki_len.getValue(), epki_len1.getValue());
        // разобрать контейнер с личным ключом (l = 128)
        err = bee2.bpkiPrivkeyUnwrap(null, key_len, 
            epki, epki_len.getValue(), pwd, 3);
        assertEquals(ERR_OK, err);
        assertEquals(32, key_len.getValue());
        err = bee2.bpkiPrivkeyUnwrap(key, key_len, 
            epki, epki_len.getValue(), pwd, 3);
        assertEquals(ERR_OK, err);
        assertEquals(32, key_len.getValue());
        assertEquals(Util.bytesToHex(src), Util.bytesToHex(key));
        assertTrue(Arrays.equals(src, key));
    }
}
