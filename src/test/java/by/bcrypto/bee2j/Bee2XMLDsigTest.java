package by.bcrypto.bee2j;

import by.bcrypto.bee2j.constants.XmlIdConstants;
import by.bcrypto.bee2j.provider.*;
import by.bcrypto.bee2j.provider.xmldsig.Bee2SignatureMethod;
import junit.framework.TestCase;

import java.security.*;
import javax.xml.crypto.dsig.*;
import java.util.Collections;
import java.util.Iterator;

import javax.xml.crypto.dsig.spec.*;
 
import javax.xml.crypto.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
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
import java.util.List;


import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class Bee2XMLDsigTest extends TestCase{

    //тестирование генерации ЭЦП из СТБ 34.101.50 Приложение Е
    public void testXMLDsigSign() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, KeyException, SAXException, IOException, ParserConfigurationException, MarshalException, XMLSignatureException, TransformerException {
        //установить провайдер

        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);

        // Create a DOM XMLSignatureFactory that will be used to generate the
        // enveloped signature
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", bee2j);

        // Create a Reference to the enveloped document (in this case we are
        // signing the whole document, so a URI of "" signifies that) and
        // also specify the Belt digest algorithm and the ENVELOPED Transform.
        Reference ref = fac.newReference
            ("", fac.newDigestMethod(XmlIdConstants.Belt, null),
             Collections.singletonList
              (fac.newTransform
                (Transform.ENVELOPED, (TransformParameterSpec) null)),
             null, null);
        // Create the SignedInfo
        SignedInfo si = fac.newSignedInfo
            (fac.newCanonicalizationMethod
             (CanonicalizationMethod.INCLUSIVE,
              (C14NMethodParameterSpec) null),
             fac.newSignatureMethod(XmlIdConstants.BignWithBelt, null),
             Collections.singletonList(ref));

        KeyPairGenerator bignKeyPairGenerator = KeyPairGenerator.getInstance("Bign","Bee2");
        BrngSecureRandom brngSecureRandom = new BrngSecureRandom();

        //используется специальная тестовая функция с константным внутренним состоянием
        brngSecureRandom.setRng(new Bee2Library.TestBrngForPK());
        bignKeyPairGenerator.initialize(128, brngSecureRandom);
        KeyPair keyPair =  bignKeyPairGenerator.generateKeyPair();
        
        // Create a KeyValue containing the Bign PublicKey that was generated
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
        dsc.setProperty("javax.xml.crypto.dsig.cacheReference", true);

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
        String parts[] = result.split("SignatureValue", 3);
        assertEquals(parts.length, 3);
        assertEquals(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>"
        + "<doc><body>text</body>"
        + "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
        + "<SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"
        + "<SignatureMethod Algorithm=\"http://www.w3.org/2009/xmldsig11#bign-with-hbelt\"/>" 
        + "<Reference URI=\"\"><Transforms>" 
        + "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms>"
        + "<DigestMethod Algorithm=\"http://www.w3.org/2009/xmldsig11#belt-hash256\"/>"
        + "<DigestValue>wHOrxc+1QSksYc3KhxzTlJ59/LS7S2EU89yQSUVQmGQ=</DigestValue></Reference></SignedInfo>"
        + "<", parts[0]);
        assertEquals(">"
        + "<KeyInfo><KeyValue><BignKeyValue xmlns=\"http://www.w3.org/2009/xmldsig11#\">"
        + "<DomainParameters><NamedCurve URN=\"http://www.w3.org/2009/xmldsig11#bign-curve256v1\"/></DomainParameters>"
        + "<PublicKey>vRpWUBedeeA/zuSdTCvV3fVM5G0M8R5P+Hv3qJCFf9B6xqYDYejIFzSRaG1GGygmGQwu2lkJBUqa&#13;\nuE0qudmakA==</PublicKey>"
        + "</BignKeyValue></KeyValue></KeyInfo></Signature></doc>", parts[2]);
        //assertEquals("", parts[1]);
    }

    /**
     * KeySelector which retrieves the public key out of the
     * KeyValue element and returns it.
     * NOTE: If the key algorithm doesn't match signature algorithm,
     * then the public key will be ignored.
     */
    private static class KeyValueKeySelector extends KeySelector {
        public KeySelectorResult select(KeyInfo keyInfo,
                                        KeySelector.Purpose purpose,
                                        AlgorithmMethod method,
                                        XMLCryptoContext context)
            throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            Bee2SignatureMethod sm = (Bee2SignatureMethod) method;
            List<XMLStructure> list = keyInfo.getContent();

            for (int i = 0; i < list.size(); i++) {
                XMLStructure xmlStructure = list.get(i);
                if (xmlStructure instanceof KeyValue) {
                    PublicKey pk = null;
                    try {
                        pk = ((KeyValue)xmlStructure).getPublicKey();
                    } catch (KeyException ke) {
                        throw new KeySelectorException(ke);
                    }
                    //System.out.println(sm.getAlgorithm());
                    //System.out.println(pk.getAlgorithm());
                    // make sure algorithm is compatible with method
                    if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
                        return new SimpleKeySelectorResult(pk);
                    }
                }
            }
            throw new KeySelectorException("No KeyValue element found!");
        }

        static boolean algEquals(String algURI, String algName) {
            if (algName.equalsIgnoreCase("DSA") &&
                algURI.equalsIgnoreCase("http://www.w3.org/2009/xmldsig11#dsa-sha256")) {
                return true;
            } else if (algName.equalsIgnoreCase("RSA") &&
                       algURI.equalsIgnoreCase("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")) {
                return true;
            } else if (algName.equalsIgnoreCase("Bign") &&
                algURI.toLowerCase().startsWith("http://www.w3.org/2009/xmldsig11#bign")) {
                return true;
            } else {
                return false;
            }
        }
    }

    private static class SimpleKeySelectorResult implements KeySelectorResult {
        private PublicKey pk;
        SimpleKeySelectorResult(PublicKey pk) {
            this.pk = pk;
        }

        public Key getKey() { return pk; }
    }


    //тестирование верификации ЭЦП из СТБ 34.101.50 Приложение Е
    public void testXMLDsigVerify() throws NoSuchProviderException, SAXException, IOException, ParserConfigurationException, MarshalException, XMLSignatureException{
        //установить провайдер

        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);
        //System.setProperty("javax.xml.crypto.dsig.cacheReference", "true");

        String testDoc = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>"
        + "<doc><body>text</body>"
        + "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
        + "<SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"
        + "<SignatureMethod Algorithm=\"http://www.w3.org/2009/xmldsig11#bign-with-hbelt\"/>" 
        + "<Reference URI=\"\"><Transforms>" 
        + "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms>"
        + "<DigestMethod Algorithm=\"http://www.w3.org/2009/xmldsig11#belt-hash256\"/>"
        + "<DigestValue>wHOrxc+1QSksYc3KhxzTlJ59/LS7S2EU89yQSUVQmGQ=</DigestValue></Reference></SignedInfo>"
        + "<SignatureValue>sBPH2GOFDdYutrJDNeH5PkzvvFWsrzImS0If2bSmV490Taz/icD1GktFbLqrRRLp</SignatureValue>"
        + "<KeyInfo><KeyValue><BignKeyValue xmlns=\"http://www.w3.org/2009/xmldsig11#\">"
        + "<DomainParameters><NamedCurve URN=\"http://www.w3.org/2009/xmldsig11#bign-curve256v1\"/></DomainParameters>"
        + "<PublicKey>vRpWUBedeeA/zuSdTCvV3fVM5G0M8R5P+Hv3qJCFf9B6xqYDYejIFzSRaG1GGygmGQwu2lkJBUqa&#13;\nuE0qudmakA==</PublicKey>"
        + "</BignKeyValue></KeyValue></KeyInfo></Signature></doc>";

        // Instantiate the document to be signed
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        
        InputStream targetStream = new ByteArrayInputStream(testDoc.getBytes());
        Document doc = dbf.newDocumentBuilder().parse(targetStream);

        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        assertEquals(1, nl.getLength());

        // Create a DOMValidateContext and specify a KeyValue KeySelector
        // and document context
        DOMValidateContext valContext = new DOMValidateContext
            (new KeyValueKeySelector(), nl.item(0));

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", bee2j);

        XMLSignature signature = fac.unmarshalXMLSignature(valContext);
        valContext.setProperty("javax.xml.crypto.dsig.cacheReference", true);

        boolean coreValidity = signature.validate(valContext);
        boolean sv = true;
        // Check core validation status
        if (coreValidity == false) {
            System.err.println("Signature failed core validation");
            sv = signature.getSignatureValue().validate(valContext);
            System.out.println("signature validation status: " + sv);
            // check the validation status of each Reference
            Iterator<Reference> i =
                signature.getSignedInfo().getReferences().iterator();
            for (int j=0; i.hasNext(); j++) {
                boolean refValid = i.next().validate(valContext);
                System.out.println("ref["+j+"] validity status: " + refValid);
            }
        } else {
            System.out.println("Signature passed core validation");
        }
        assertEquals(true, coreValidity); 
        assertEquals(true, sv);         
    }
}
