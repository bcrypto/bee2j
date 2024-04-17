package by.bcrypto.bee2j;

import by.bcrypto.bee2j.provider.*;
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

public class XMLDSigTest extends TestCase{

    //тестирование генерации ЭЦП 
    public void testXMLDsigSign() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, KeyException, SAXException, IOException, ParserConfigurationException, MarshalException, XMLSignatureException, TransformerException {
        //установить провайдер

        Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        Security.addProvider(bee2j);

        // Instantiate the document to be signed
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        String testDoc = "<doc><body>text</body></doc>";
        InputStream targetStream = new ByteArrayInputStream(testDoc.getBytes());
        Document doc = dbf.newDocumentBuilder().parse(targetStream);

        // Create a DOM XMLSignatureFactory that will be used to generate the
        // enveloped signature
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", bee2j);

        // Create a Reference to the enveloped document (in this case we are
        // signing the whole document, so a URI of "" signifies that) and
        // also specify the Belt digest algorithm and the ENVELOPED Transform.
        //Transform t = new Transform(doc, Transform.ENVELOPED);
        Transform t = fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
        Reference ref = fac.newReference
            ("", fac.newDigestMethod(DigestMethod.SHA256, null),
             Collections.singletonList(t),
             null, null);
        // Create the SignedInfo
        SignedInfo si = fac.newSignedInfo
            (fac.newCanonicalizationMethod
             (CanonicalizationMethod.INCLUSIVE,
              (C14NMethodParameterSpec) null),
             fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
             Collections.singletonList(ref));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        
        // Create a KeyValue containing the Bign PublicKey that was generated
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(keyPair.getPublic());

        // Create a KeyInfo and add the KeyValue to it
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
        
        // Create a DOMSignContext and specify the RSA PrivateKey and
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
        //System.out.println(result);
        String parts[] = result.split("SignatureValue", 3);
        assertEquals(parts.length, 3);
        assertEquals(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>"
        + "<doc><body>text</body>"
        + "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
        + "<SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"
        + "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>" 
        + "<Reference URI=\"\"><Transforms>" 
        + "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms>"
        + "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
        + "<DigestValue>T6841cUeIWXCGd5/I9LRd4tykHG22xVc+T0orDTP+Mw=</DigestValue></Reference></SignedInfo>"
        + "<", parts[0]);

        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        assertEquals(1, nl.getLength());

        // Create a DOMValidateContext and specify a KeyValue KeySelector
        // and document context
        DOMValidateContext valContext = new DOMValidateContext
            (new KeyValueKeySelector(), nl.item(0));

        XMLSignature signature1 = fac.unmarshalXMLSignature(valContext);

        boolean coreValidity = signature1.validate(valContext);
        assertEquals(true, coreValidity);
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
            SignatureMethod sm = (SignatureMethod) method;
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

        //Bee2SecurityProvider bee2j = new Bee2SecurityProvider();
        //Security.addProvider(bee2j);
        //System.setProperty("javax.xml.crypto.dsig.cacheReference", "true");
        
        String testDoc = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>"
        + "<doc><body>text</body>"
        + "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
        + "<SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"
        + "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>" 
        + "<Reference URI=\"\"><Transforms>" 
        + "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms>"
        + "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
        + "<DigestValue>T6841cUeIWXCGd5/I9LRd4tykHG22xVc+T0orDTP+Mw=</DigestValue></Reference></SignedInfo>"
        + "<SignatureValue>TWfz7F5aG0AOPL+gJpyeuA1lseiGpUCMfzi1SJGl3MewxRP/Enk45WUkjOGLpPG/OEX5aQI6WKU4&#13;\n"
        + "PQ3Zmfu85TtbEvbENqqieDpJzSqMxHV/V4Mk84TZRkTXzgQaul4FSYtvx8YnHqStr5OwI5Ocqmc5&#13;\n"
        + "3i+NvK4njyZ58ZhmpFDydmRGhqjOa40MSlngCcCZZ5S4uV9vb0spua7jCnsodzoqYpfOW/GWsYg0&#13;\n"
        + "6NHUqSUEKkPtGDTUitJB85d4OdcNsn8FGibsIy7mVlzE0WWdCaX5tfz9R1RAF1Y95hdnYNFLSU5a&#13;\n"
        + "DdR007PR/vomJeK+YeoQOfuoX/QwPknv2FiXdg==</SignatureValue><KeyInfo><KeyValue>"
        + "<RSAKeyValue><Modulus>odi6aH8uPv6T/GAOKMU+yl/xtvb6k1a3aHZvVgaic8cMtb1qmujME5BH4dpm4QMwALQXa7OF36Uw&#13;\n"
        + "BLKBQ+HBDJJj+vkslCNekavZUpUY4gdfsUbHBGtc/1THCmzbWGzr0OosnIajvKvuU3RTN9Bu7a21&#13;\n"
        + "zJBdzaCdO0jBmE7Oas0dhSiL533dSxzzwh/s8OYX77+LwlpGKQQywPjd4YwP3sFTEDp/RNLx9Zec&#13;\n"
        + "Y1MHyKcj1Wrwy+9K1tAv5EDpALQ3aK3gv9YANNfPw4YQNGIbeCT63I/2QZ2h3yCNxtgtKxQPL87G&#13;\n"
        + "EgGyfUMSMoX5sglaMSql4qXAwiO/m854YMFisw==</Modulus><Exponent>AQAB</Exponent>"
        + "</RSAKeyValue></KeyValue></KeyInfo></Signature></doc>";
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

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        XMLSignature signature = fac.unmarshalXMLSignature(valContext);
        
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
