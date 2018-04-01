package by.bcrypto.bee2j;

import by.bcrypto.bee2j.provider.BrngSecureRandom;
import by.bcrypto.bee2j.provider.BeltKey;
import com.sun.jna.Pointer;
import junit.framework.TestCase;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

import by.bcrypto.bee2j.provider.Bee2SecurityProvider;

import javax.crypto.*;

public class Bee2ProviderTest extends TestCase{


    //тестирование алгоритма хэширования из СТБ 34.101.31
    public void testBeltMessageDigest() throws NoSuchAlgorithmException, NoSuchProviderException {
        //установить провайдер

        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);

        //Тест A.24 из СТБ 34.101.31

        Bee2Library bee2 = Bee2Library.INSTANCE;
        byte[] hash;
        int n = 13;
        MessageDigest beltH = MessageDigest.getInstance("BeltHash","Bee2");

        Pointer p = bee2.beltH();

        //src - входные данные из теста A.24 из СТБ 34.101.31, srcPad - дополнение входных данных из A.24 до входных данных A.25

        byte[] src = p.getByteArray(0, n);
        byte[] srcPad = p.getByteArray(n, 19);
        beltH.update(src);
        hash = beltH.digest();
        int[] intHash = new int[beltH.getDigestLength()];
        for(int i = 0; i < hash.length; i++)
        {
            intHash[i] = hash[i]&0xff;
        }
        int[] test1 = {0xab, 0xef, 0x97, 0x25,
                0xd4, 0xc5, 0xa8, 0x35,
                0x97, 0xa3, 0x67, 0xD1,
                0x44, 0x94, 0xcc, 0x25,
                0x42, 0xf2, 0x0f, 0x65,
                0x9d, 0xdf, 0xec, 0xc9,
                0x61, 0xa3, 0xec, 0x55,
                0x0c, 0xba, 0x8c, 0x75
        };
        assertTrue(Arrays.equals(test1,intHash));

        //Тест A.25 из СТБ 34.101.31

        int[] test2 = {0x74, 0x9e, 0x4c, 0x36,
                0x53, 0xae, 0xce, 0x5e,
                0x48, 0xdb, 0x47, 0x61,
                0x22, 0x77, 0x42, 0xeb,
                0x6d, 0xbe, 0x13, 0xf4,
                0xa8, 0x0f, 0x7b, 0xef,
                0xf1, 0xa9, 0xcf, 0x8d,
                0x10, 0xee, 0x77, 0x86
        };
        hash = beltH.digest(srcPad);
        for(int i = 0; i < hash.length; i++)
        {
            intHash[i] = hash[i]&0xff;
        }
        assertTrue(Arrays.equals(test2,intHash));

        //Тест A.26 из СТБ 34.101.31

        int[] test3 = {0x9d, 0x02, 0xee, 0x44,
                0x6f, 0xb6, 0xa2, 0x9f,
                0xe5, 0xc9, 0x82, 0xd4,
                0xb1, 0x3a, 0xf9, 0xd3,
                0xe9, 0x08, 0x61, 0xbc,
                0x4c, 0xef, 0x27, 0xcf,
                0x30, 0x6b, 0xfb, 0x0b,
                0x17, 0x4a, 0x15, 0x4a
        };
        beltH.reset();
        hash = beltH.digest(p.getByteArray(0,48));
        for(int i = 0; i < hash.length; i++)
        {
            intHash[i] = hash[i]&0xff;
        }
        assertTrue(Arrays.equals(test3,intHash));
    }
    //тестирование алгоритма генерации ключей из СТБ 34.101.45
    public void testBignKeyPairGenerator() throws NoSuchProviderException, NoSuchAlgorithmException {

        //Тест Г.1 из СТБ 34.101.45

        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);

        Bee2Library bee2 = Bee2Library.INSTANCE;
        KeyPairGenerator bignKeyPairGenerator = KeyPairGenerator.getInstance("Bign","Bee2");
        BrngSecureRandom brngSecureRandom = new BrngSecureRandom();

        //используется специальная тестовая функция с константным внутренним состоянием
        brngSecureRandom.setRng( new Bee2Library.TestBrngForPK());
        bignKeyPairGenerator.initialize(128, brngSecureRandom);
        KeyPair keyPair =  bignKeyPairGenerator.generateKeyPair();
        PrivateKey privateKey =  keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        //тест личного ключа
        byte[] byte_privateKey = privateKey.getEncoded();
        String hexPrivateKeyString = new String();
        for(int i = 0;i<byte_privateKey.length;i++)
            hexPrivateKeyString = hexPrivateKeyString.concat(Integer.toHexString(0x100| byte_privateKey[i]&0xff).substring(1).toUpperCase());
        assertEquals(hexPrivateKeyString, "1F66B5B84B7339674533F0329C74F218"+
                "34281FED0732429E0C79235FC273E269");

        //тест открытого ключа
        byte[] byte_publicKey = publicKey.getEncoded();
        String hexPublicKeyString = new String();
        for(int i = 0;i<byte_publicKey.length;i++)
            hexPublicKeyString = hexPublicKeyString.concat(Integer.toHexString(0x100| byte_publicKey[i]&0xff).substring(1).toUpperCase());
        assertEquals(hexPublicKeyString, "BD1A5650179D79E03FCEE49D4C2BD5DD"+
                "F54CE46D0CF11E4FF87BF7A890857FD0"+
                "7AC6A60361E8C8173491686D461B2826"+
                "190C2EDA5909054A9AB84D2AB9D99A90");
    }
    //тестирование ГПСЧ brng-ctr-hbelt  из СТБ 34.101.47
    public void testBrngSecureRandom() throws NoSuchProviderException, NoSuchAlgorithmException {
        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);

        // Тест Б.2 из СТБ 34.101.47

        Bee2Library bee2 = Bee2Library.INSTANCE;
        BrngSecureRandom brngSecureRandom = new BrngSecureRandom();
        brngSecureRandom.setRng(new Bee2Library.TestBrngFunc());
        Pointer p = bee2.beltH();
        byte[] byte_test = p.getByteArray(0, 96);
        brngSecureRandom.engineSetSeed(p.getByteArray(192,32));
        brngSecureRandom.engineNextBytes(byte_test);
        String test = new String();
        for(int i=0;i<96;i++)
            test = test.concat(Integer.toHexString(0x100| byte_test[i]&0xff).substring(1).toUpperCase());
        assertEquals(test, "1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269" +
                "4C0E74B2CD5811AD21F23DE7E0FA742C3ED6EC483C461CE15C33A77AA308B7D2" +
                "0F51D91347617C20BD4AB07AEF4F26A1AD1362A8F9A3D42FBE1B8E6F1C88AAD5"
        );

        //если скопировать тест из bee2, то получатся строки внешне одинаковые, однако тест не работает
    }
    //тестирование алгоритма шифрования из СТБ 34.101.31 в режиме ECB
    public void testBeltCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //Тест A.6 из СТБ 34.101.31
        Bee2Library bee2 = Bee2Library.INSTANCE;
        byte[] encr_data = new byte[48];
        bee2.beltECBEncr(encr_data,bee2.beltH().getByteArray(0,48),48,bee2.beltH().getByteArray(128,32),32);
        String test = new String();
        for(int i=0;i<48;i++)
            test = test.concat(Integer.toHexString(0x100| encr_data[i]&0xff).substring(1).toUpperCase());
        assertEquals(test, "69CCA1C93557C9E3D66BC3E0FA88FA6E"+
                "5F23102EF109710775017F73806DA9DC"+
                "46FB2ED2CE771F26DCB5E5D1569F9AB0");


        //на интерфейсах Java

        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);
        BeltKey beltKey = new BeltKey(bee2.beltH().getByteArray(128,32));
        Cipher beltCipher = Cipher.getInstance("Belt","Bee2");
        beltCipher.init(Cipher.ENCRYPT_MODE, beltKey);
        encr_data = beltCipher.doFinal(bee2.beltH().getByteArray(0,48),0,48);
        test = new String();
        for(int i=0;i<48;i++)
            test = test.concat(Integer.toHexString(0x100| encr_data[i]&0xff).substring(1).toUpperCase());
        assertEquals(test, "69CCA1C93557C9E3D66BC3E0FA88FA6E"+
                "5F23102EF109710775017F73806DA9DC"+
                "46FB2ED2CE771F26DCB5E5D1569F9AB0");

    }

    //тестирование ЭЦП  из СТБ 34.101.45
    /*"TODO: resolve this problem. For now I don't know a reason why this test is failed on jenkins' server. On my local machine it's ok.")
    public void testBignSignature() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);

        //выработка и проверка ЭЦП через интерфейсы Java
        Bee2Library bee2 = Bee2Library.INSTANCE;
        Signature bignSignature = Signature.getInstance("Bign","Bee2");
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
    */
    //тестирование имитовставки из СТБ 34.101.31
    public void testBeltMAC() throws InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);

        //Тест A.18 из СТБ 34.101.31

        Bee2Library bee2 = Bee2Library.INSTANCE;
        byte[] res = new byte[8];

        assertEquals(bee2.beltMAC(res, bee2.beltH().getByteArray(0,48), 48, bee2.beltH().getByteArray(128,32), 32),0);
        String stringMAC = new String();
        for(int i=0;i<8;i++)
            stringMAC = stringMAC.concat(Integer.toHexString(0x100| res[i]&0xff).substring(1).toUpperCase());
        assertEquals(stringMAC,"2DAB59771B4B16D0");

        //Тест на интерфейсах Java

        Mac beltMAC = Mac.getInstance("BeltMAC", "Bee2");
        DSAParameterSpec stubSpec = new DSAParameterSpec(new BigInteger("1"),new BigInteger("1"),new BigInteger("1"));
        beltMAC.init(new BeltKey(bee2.beltH().getByteArray(128,32)), stubSpec);
        beltMAC.update(bee2.beltH().getByteArray(0,48),0,48);
        res = beltMAC.doFinal();
        stringMAC = new String();
        for(int i=0;i<8;i++)
            stringMAC = stringMAC.concat(Integer.toHexString(0x100| res[i]&0xff).substring(1).toUpperCase());
        assertEquals(stringMAC,"2DAB59771B4B16D0");

    }
}

