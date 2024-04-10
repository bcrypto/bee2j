package by.bcrypto.bee2j;

import by.bcrypto.bee2j.constants.JceNameConstants;
import by.bcrypto.bee2j.constants.XmlIdConstants;
import by.bcrypto.bee2j.provider.*;
import com.sun.jna.Pointer;
import junit.framework.TestCase;

import java.security.*;
import java.util.Arrays;
import javax.xml.crypto.dsig.*;
import java.util.Collections;
import javax.xml.crypto.dsig.spec.*;
 
import javax.xml.crypto.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class Bee2XMLDsigTest extends TestCase{

    //тестирование алгоритма хэширования из СТБ 34.101.31
    public void testBeltMessageDigest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, KeyException, SAXException, IOException, ParserConfigurationException, MarshalException, XMLSignatureException, TransformerException {
        //установить провайдер

        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);

        //Тест A.24 из СТБ 34.101.31

        Bee2Library bee2 = Bee2Library.INSTANCE;
        byte[] hash;
        int n = 13;
        MessageDigest beltH = MessageDigest.getInstance(JceNameConstants.Belt, JceNameConstants.ProviderName);

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

        // Create a DOM XMLSignatureFactory that will be used to generate the
        // enveloped signature
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", bee2j);

        // Create a Reference to the enveloped document (in this case we are
        // signing the whole document, so a URI of "" signifies that) and
        // also specify the SHA1 digest algorithm and the ENVELOPED Transform.
        Reference ref = fac.newReference
            ("", fac.newDigestMethod(XmlIdConstants.Belt, null),
             Collections.singletonList
              (fac.newTransform
                (Transform.ENVELOPED, (TransformParameterSpec) null)),
             null, null);
        // Create the SignedInfo
        SignedInfo si = fac.newSignedInfo
            (fac.newCanonicalizationMethod
             (CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
              (C14NMethodParameterSpec) null),
             fac.newSignatureMethod(XmlIdConstants.BignWithBelt, null),
             Collections.singletonList(ref));

        KeyPairGenerator bignKeyPairGenerator = KeyPairGenerator.getInstance("Bign","Bee2");
        BrngSecureRandom brngSecureRandom = new BrngSecureRandom();

        //используется специальная тестовая функция с константным внутренним состоянием
        brngSecureRandom.setRng(new Bee2Library.TestBrngForPK());
        bignKeyPairGenerator.initialize(128, brngSecureRandom);
        KeyPair keyPair =  bignKeyPairGenerator.generateKeyPair();
        
        // Create a KeyValue containing the DSA PublicKey that was generated
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(keyPair.getPublic());

        // Create a KeyInfo and add the KeyValue to it
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
        // Instantiate the document to be signed
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        String testDoc = "<doc><body>text</body></doc>";
        InputStream targetStream = new ByteArrayInputStream(testDoc.getBytes());
        Document doc = dbf.newDocumentBuilder().parse(targetStream);

        // Create a DOMSignContext and specify the DSA PrivateKey and
        // location of the resulting XMLSignature's parent element
        DOMSignContext dsc = new DOMSignContext
            (keyPair.getPrivate(), doc.getDocumentElement());

        // Create the XMLSignature (but don't sign it yet)
        XMLSignature signature = fac.newXMLSignature(si, ki);

        // Marshal, generate (and sign) the enveloped signature
        signature.sign(dsc);

        // output the resulting document
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));
        String result = os.toString();
        assertEquals(result, "");
    }
}
