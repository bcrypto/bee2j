package by.bcrypto.bee2j;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;

import by.bcrypto.bee2j.constants.JceNameConstants;
import by.bcrypto.bee2j.der.DerBitString;
import by.bcrypto.bee2j.der.DerSequence;
import by.bcrypto.bee2j.der.DerValue;
import by.bcrypto.bee2j.provider.*;
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
        DerSequence der = new DerSequence(encodedKey);
        assertEquals("[DerValue, tag=0, length=0]", der.toString());
        assertEquals(DerValue.tag_Sequence, der.getTag());
        assertEquals("[DerValue, tag=48, length=125]", der.toString());
        ArrayList<DerValue> items = der.getSequence();
        assertEquals(DerValue.tag_Sequence, items.get(0).getTag());
        assertEquals(DerValue.tag_BitString, items.get(1).getTag());
        DerBitString derKey = (DerBitString) items.get(1);
        byte[] key = derKey.getBitString();
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

    //тестирование ЭЦП  из СТБ 34.101.45 (хэш из 34.101.77)
    public void testBignBash256Signature() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);

        //выработка и проверка ЭЦП через интерфейсы Java
        Bee2Library bee2 = Bee2Library.INSTANCE;
        Signature bignSignature = Signature.getInstance(JceNameConstants.BignWithBash256, JceNameConstants.ProviderName);
        KeyPairGenerator bignKeyPairGenerator = KeyPairGenerator.getInstance("Bign","Bee2");
        KeyPair bignKeyPair =  bignKeyPairGenerator.generateKeyPair();
        PrivateKey privateKey = bignKeyPair.getPrivate();
        PublicKey publicKey = bignKeyPair.getPublic();
        bignSignature.initSign(privateKey);
        byte[] data = bee2.beltH().getByteArray(0,13);
        bignSignature.update(data,0,13);
        byte[] sig = bignSignature.sign();
        bignSignature.initVerify(publicKey);
        bignSignature.update(data,0,13);
        assertTrue(bignSignature.verify(sig));
    }

    public void testBignBash384Signature() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);

        //выработка и проверка ЭЦП через интерфейсы Java
        Bee2Library bee2 = Bee2Library.INSTANCE;
        Signature bignSignature = Signature.getInstance(JceNameConstants.BignWithBash384, JceNameConstants.ProviderName);
        KeyPairGenerator bignKeyPairGenerator = KeyPairGenerator.getInstance("Bign","Bee2");
        bignKeyPairGenerator.initialize(192, new BrngSecureRandom());
        KeyPair bignKeyPair =  bignKeyPairGenerator.generateKeyPair();
        PrivateKey privateKey = bignKeyPair.getPrivate();
        PublicKey publicKey = bignKeyPair.getPublic();
        bignSignature.initSign(privateKey);
        byte[] data = bee2.beltH().getByteArray(0,13);
        bignSignature.update(data,0,13);
        byte[] sig = bignSignature.sign();
        bignSignature.initVerify(publicKey);
        bignSignature.update(data,0,13);
        assertTrue(bignSignature.verify(sig));
    }

    public void testBignBash512Signature() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);

        //выработка и проверка ЭЦП через интерфейсы Java
        Bee2Library bee2 = Bee2Library.INSTANCE;
        Signature bignSignature = Signature.getInstance(JceNameConstants.BignWithBash512, JceNameConstants.ProviderName);
        KeyPairGenerator bignKeyPairGenerator = KeyPairGenerator.getInstance("Bign","Bee2");
        bignKeyPairGenerator.initialize(256, new BrngSecureRandom());
        KeyPair bignKeyPair =  bignKeyPairGenerator.generateKeyPair();
        PrivateKey privateKey = bignKeyPair.getPrivate();
        PublicKey publicKey = bignKeyPair.getPublic();
        bignSignature.initSign(privateKey);
        byte[] data = bee2.beltH().getByteArray(0,13);
        bignSignature.update(data,0,13);
        byte[] sig = bignSignature.sign();
        bignSignature.initVerify(publicKey);
        bignSignature.update(data,0,13);
        assertTrue(bignSignature.verify(sig));
    }

    public void testBeltModes() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException 
    {
        Bee2Library bee2 = Bee2Library.INSTANCE;
        byte[] encr_data = new byte[48];
        
        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);

        // belt-ecb: тест A.9-1
        BeltKey beltKey = new BeltKey(bee2.beltH().getByteArray(128,32));
        Cipher beltCipher = Cipher.getInstance("BeltECB","Bee2");
        beltCipher.init(Cipher.ENCRYPT_MODE, beltKey);
        byte[] src = bee2.beltH().getByteArray(0,48);
        encr_data = beltCipher.doFinal(src,0,48);
        assertEquals("69CCA1C93557C9E3D66BC3E0FA88FA6E"+
                "5F23102EF109710775017F73806DA9DC"+
                "46FB2ED2CE771F26DCB5E5D1569F9AB0", Util.bytesToHex(encr_data));
        // belt-cbc: тест A.11-1
        Cipher beltCBC = Cipher.getInstance("BeltCBC","Bee2");
        byte[] IV = bee2.beltH().getByteArray(192,16);
        beltCBC.init(Cipher.ENCRYPT_MODE, beltKey, new IvParameterSpec(IV));
        encr_data = beltCBC.doFinal(src, 0, 48);
        String str11 = "10116EFAE6AD58EE14852E11DA1B8A74"+
        "5CF2480E8D03F1C19492E53ED3A70F60"+
        "657C1EE8C0E0AE5B58388BF8A68E3309";
        assertEquals(str11, Util.bytesToHex(encr_data));
        // test update
        byte[] encrBuf = new byte[48];
        int i = 0;
        i += beltCBC.update(src, 0, 16, encrBuf, i);
        i += beltCBC.update(src, 16, 16, encrBuf, i);
        i += beltCBC.doFinal(src, 32, 16, encrBuf, i);
        assertEquals(48, i);
        assertEquals(str11, Util.bytesToHex(encrBuf));
        // test full buffered mode
        i = 0;
        i += beltCBC.update(src, 0, 15, encrBuf, i);
        i += beltCBC.update(src, 15, 17, encrBuf, i);
        i += beltCBC.doFinal(src, 32, 16, encrBuf, i);
        assertEquals(48, i);
        assertEquals(str11, Util.bytesToHex(encrBuf));
        // test partial buffered mode
        i = 0;
        i += beltCBC.update(src, 0, 16, encrBuf, i);
        i += beltCBC.update(src, 16, 15, encrBuf, i);
        i += beltCBC.doFinal(src, 31, 17, encrBuf, i);
        assertEquals(48, i);
        assertEquals(str11, Util.bytesToHex(encrBuf));

        // belt-cfb: тест A.13
        Cipher beltCFB = Cipher.getInstance("BeltCFB","Bee2");
        beltCFB.init(Cipher.ENCRYPT_MODE, beltKey, new IvParameterSpec(IV));
        encr_data = beltCFB.doFinal(src, 0, 48);
        String str13 = "C31E490A90EFA374626CC99E4B7B8540" +
		"A6E48685464A5A06849C9CA769A1B0AE" +
		"55C2CC5939303EC832DD2FE16C8E5A1B";
        assertEquals(str13, Util.bytesToHex(encr_data));

        // belt-ctr: тест A.15
        Cipher beltCTR = Cipher.getInstance("BeltCTR","Bee2");
        beltCTR.init(Cipher.ENCRYPT_MODE, beltKey, new IvParameterSpec(IV));
        encr_data = beltCTR.doFinal(src, 0, 48);
        String str15 = "52C9AF96FF50F64435FC43DEF56BD797" +
		"D5B5B1FF79FB41257AB9CDF6E63E81F8" +
		"F00341473EAE409833622DE05213773A";
        assertEquals(str15, Util.bytesToHex(encr_data));

        // belt-mac: тест A.17-1
        Cipher beltMAC = Cipher.getInstance("BeltMAC","Bee2");
        beltMAC.init(Cipher.ENCRYPT_MODE, beltKey);
        byte[] mac = beltMAC.doFinal(bee2.beltH().getByteArray(0,13), 0, 13);
        String str17 = "7260DA60138F96C9";
        assertEquals(str17, Util.bytesToHex(mac));
        // test update
        beltMAC.init(Cipher.ENCRYPT_MODE, beltKey);
        beltMAC.update(bee2.beltH().getByteArray(0,13));
        mac = beltMAC.doFinal();
        assertEquals(str17, Util.bytesToHex(mac));

        // belt-dwp: тест A.19-1 
        Cipher beltDWP = Cipher.getInstance("BeltDWP","Bee2");
        beltDWP.init(Cipher.ENCRYPT_MODE, beltKey, new IvParameterSpec(IV));
        beltDWP.updateAAD(src, 16, 32);
        encr_data = beltDWP.update(src, 0, 16);
        mac = beltDWP.doFinal();
        String str19 = "52C9AF96FF50F64435FC43DEF56BD797";
        assertEquals(str19, Util.bytesToHex(encr_data));
        assertEquals("3B2E0AEB2B91854B", Util.bytesToHex(mac));
    }
}
