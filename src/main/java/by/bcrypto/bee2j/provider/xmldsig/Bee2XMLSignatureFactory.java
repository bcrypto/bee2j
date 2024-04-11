package by.bcrypto.bee2j.provider.xmldsig;


import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.DigestMethodParameterSpec;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.jcp.xml.dsig.internal.dom.DOMCanonicalizationMethod;
import org.apache.jcp.xml.dsig.internal.dom.DOMManifest;
//import org.apache.jcp.xml.dsig.internal.dom.DOMReference;
import org.apache.jcp.xml.dsig.internal.dom.DOMSignatureProperties;
import org.apache.jcp.xml.dsig.internal.dom.DOMSignatureProperty;
//import org.apache.jcp.xml.dsig.internal.dom.DOMSignedInfo;
import org.apache.jcp.xml.dsig.internal.dom.DOMTransform;
import org.apache.jcp.xml.dsig.internal.dom.DOMXMLObject;
//import org.apache.jcp.xml.dsig.internal.dom.DOMXMLSignature;

import by.bcrypto.bee2j.constants.XmlIdConstants;

/**
 * DOM-based implementation of XMLSignatureFactory.
 *
 */
public final class Bee2XMLSignatureFactory extends XMLSignatureFactory {

    /**
     * Initializes a new instance of this class.
     */
    public Bee2XMLSignatureFactory() {}

    @Override
    public XMLSignature newXMLSignature(SignedInfo si, KeyInfo ki) {
        return new Bee2XMLSignature(si, ki, null, null, null);
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public XMLSignature newXMLSignature(SignedInfo si, KeyInfo ki,
        List objects, String id, String signatureValueId) {
        return new Bee2XMLSignature(si, ki, objects, id, signatureValueId);
    }

    @Override
    public Reference newReference(String uri, DigestMethod dm) {
        return newReference(uri, dm, null, null, null);
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public Reference newReference(String uri, DigestMethod dm, List transforms,
        String type, String id) {
        return new Bee2Reference(uri, type, dm, transforms, id, getProvider());
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public Reference newReference(String uri, DigestMethod dm,
        List appliedTransforms, Data result, List transforms, String type,
        String id) {
        if (appliedTransforms == null) {
            throw new NullPointerException("appliedTransforms cannot be null");
        }
        if (appliedTransforms.isEmpty()) {
            throw new NullPointerException("appliedTransforms cannot be empty");
        }
        if (result == null) {
            throw new NullPointerException("result cannot be null");
        }
        return new Bee2Reference
            (uri, type, dm, appliedTransforms, result, transforms, id, getProvider());
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public Reference newReference(String uri, DigestMethod dm, List transforms,
        String type, String id, byte[] digestValue) {
        if (digestValue == null) {
            throw new NullPointerException("digestValue cannot be null");
        }
        return new Bee2Reference
            (uri, type, dm, null, null, transforms, id, digestValue, getProvider());
    }

    @Override
    @SuppressWarnings({ "rawtypes" })
    public SignedInfo newSignedInfo(CanonicalizationMethod cm,
        SignatureMethod sm, List references) {
        return newSignedInfo(cm, sm, references, null);
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public SignedInfo newSignedInfo(CanonicalizationMethod cm,
        SignatureMethod sm, List references, String id) {
        return new Bee2SignedInfo(cm, sm, references, id);
    }

    // Object factory methods
    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public XMLObject newXMLObject(List content, String id, String mimeType,
        String encoding) {
        return new DOMXMLObject(content, id, mimeType, encoding);
    }

    @Override
    @SuppressWarnings({ "rawtypes" })
    public Manifest newManifest(List references) {
        return newManifest(references, null);
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public Manifest newManifest(List references, String id) {
        return new DOMManifest(references, id);
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public SignatureProperties newSignatureProperties(List props, String id) {
        return new DOMSignatureProperties(props, id);
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public SignatureProperty newSignatureProperty
        (List info, String target, String id) {
        return new DOMSignatureProperty(info, target, id);
    }

    @Override
    public XMLSignature unmarshalXMLSignature(XMLValidateContext context)
        throws MarshalException {

        if (context == null) {
            throw new NullPointerException("context cannot be null");
        }
        return unmarshal(((DOMValidateContext) context).getNode(), context);
    }

    @Override
    public XMLSignature unmarshalXMLSignature(XMLStructure xmlStructure)
        throws MarshalException {

        if (xmlStructure == null) {
            throw new NullPointerException("xmlStructure cannot be null");
        }
        if (!(xmlStructure instanceof javax.xml.crypto.dom.DOMStructure)) {
            throw new ClassCastException("xmlStructure must be of type DOMStructure");
        }
        return unmarshal
            (((javax.xml.crypto.dom.DOMStructure) xmlStructure).getNode(),
             new UnmarshalContext());
    }

    private static class UnmarshalContext extends DOMCryptoContext {
        UnmarshalContext() {}
    }

    private XMLSignature unmarshal(Node node, XMLCryptoContext context)
        throws MarshalException {

        node.normalize();

        Element element = null;
        if (node.getNodeType() == Node.DOCUMENT_NODE) {
            element = ((Document) node).getDocumentElement();
        } else if (node.getNodeType() == Node.ELEMENT_NODE) {
            element = (Element) node;
        } else {
            throw new MarshalException
                ("Signature element is not a proper Node");
        }

        // check tag
        String tag = element.getLocalName();
        String namespace = element.getNamespaceURI();
        if (tag == null || namespace == null) {
            throw new MarshalException("Document implementation must " +
                "support DOM Level 2 and be namespace aware");
        }
        if ("Signature".equals(tag) && XMLSignature.XMLNS.equals(namespace)) {
            try {
                return new Bee2XMLSignature(element, context, getProvider());
            } catch (MarshalException me) {
                throw me;
            } catch (Exception e) {
                throw new MarshalException(e);
            }
        } else {
            throw new MarshalException("Invalid Signature tag: " + namespace + ":" + tag);
        }
    }

    @Override
    public boolean isFeatureSupported(String feature) {
        if (feature == null) {
            throw new NullPointerException();
        } else {
            return false;
        }
    }

    @Override
    public DigestMethod newDigestMethod(String algorithm,
        DigestMethodParameterSpec params) throws NoSuchAlgorithmException,
        InvalidAlgorithmParameterException {
        if (algorithm == null) {
            throw new NullPointerException();
        }
        if (algorithm.equals(XmlIdConstants.Belt)) {
            return new Bee2DigestMethod.Belt(params);
        } else if (algorithm.equals(XmlIdConstants.Bash256)) {
            return new Bee2DigestMethod.Bash256(params);
        } else if (algorithm.equals(XmlIdConstants.Bash384)) {
            return new Bee2DigestMethod.Bash384(params);
        } else if (algorithm.equals(XmlIdConstants.Bash512)) {
            return new Bee2DigestMethod.Bash512(params);
        } else if (algorithm.equals(DigestMethod.SHA1)) {
            return new Bee2DigestMethod.SHA1(params);
        } else if (algorithm.equals(Bee2DigestMethod.SHA224)) {
            return new Bee2DigestMethod.SHA224(params);
        } else if (algorithm.equals(DigestMethod.SHA256)) {
            return new Bee2DigestMethod.SHA256(params);
        } else if (algorithm.equals(Bee2DigestMethod.SHA384)) {
            return new Bee2DigestMethod.SHA384(params);
        } else if (algorithm.equals(DigestMethod.SHA512)) {
            return new Bee2DigestMethod.SHA512(params);
        } else if (algorithm.equals(DigestMethod.RIPEMD160)) {
            return new Bee2DigestMethod.RIPEMD160(params);
        } else if (algorithm.equals(Bee2DigestMethod.WHIRLPOOL)) {
            return new Bee2DigestMethod.WHIRLPOOL(params);
        } else if (algorithm.equals(Bee2DigestMethod.SHA3_224)) {
            return new Bee2DigestMethod.SHA3_224(params);
        } else if (algorithm.equals(Bee2DigestMethod.SHA3_256)) {
            return new Bee2DigestMethod.SHA3_256(params);
        } else if (algorithm.equals(Bee2DigestMethod.SHA3_384)) {
            return new Bee2DigestMethod.SHA3_384(params);
        } else if (algorithm.equals(Bee2DigestMethod.SHA3_512)) {
            return new Bee2DigestMethod.SHA3_512(params);
        } else {
            throw new NoSuchAlgorithmException("unsupported algorithm");
        }
    }

    @Override
    public SignatureMethod newSignatureMethod(String algorithm,
        SignatureMethodParameterSpec params) throws NoSuchAlgorithmException,
        InvalidAlgorithmParameterException {
        if (algorithm == null) {
            throw new NullPointerException();
        }
        if (algorithm.equals(XmlIdConstants.BignWithBelt)) {
            return new Bee2SignatureMethod.BignWithBelt(params);
        } else if (algorithm.equals(SignatureMethod.RSA_SHA1)) {
            return new Bee2SignatureMethod.SHA1withRSA(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_SHA224)) {
            return new Bee2SignatureMethod.SHA224withRSA(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_SHA256)) {
            return new Bee2SignatureMethod.SHA256withRSA(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_SHA384)) {
            return new Bee2SignatureMethod.SHA384withRSA(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_SHA512)) {
            return new Bee2SignatureMethod.SHA512withRSA(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_RIPEMD160)) {
            return new Bee2SignatureMethod.RIPEMD160withRSA(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_SHA1_MGF1)) {
            return new Bee2SignatureMethod.SHA1withRSAandMGF1(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_SHA224_MGF1)) {
            return new Bee2SignatureMethod.SHA224withRSAandMGF1(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_SHA256_MGF1)) {
            return new Bee2SignatureMethod.SHA256withRSAandMGF1(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_SHA384_MGF1)) {
            return new Bee2SignatureMethod.SHA384withRSAandMGF1(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_SHA512_MGF1)) {
            return new Bee2SignatureMethod.SHA512withRSAandMGF1(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_SHA3_224_MGF1)) {
            return new Bee2SignatureMethod.SHA3_224withRSAandMGF1(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_SHA3_256_MGF1)) {
            return new Bee2SignatureMethod.SHA3_256withRSAandMGF1(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_SHA3_384_MGF1)) {
            return new Bee2SignatureMethod.SHA3_384withRSAandMGF1(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_SHA3_512_MGF1)) {
            return new Bee2SignatureMethod.SHA3_512withRSAandMGF1(params);
        } else if (algorithm.equals(Bee2SignatureMethod.RSA_RIPEMD160_MGF1)) {
            return new Bee2SignatureMethod.RIPEMD160withRSAandMGF1(params);
        } else if (algorithm.equals(SignatureMethod.DSA_SHA1)) {
            return new Bee2SignatureMethod.SHA1withDSA(params);
        } else if (algorithm.equals(Bee2SignatureMethod.DSA_SHA256)) {
            return new Bee2SignatureMethod.SHA256withDSA(params);
        } else if (algorithm.equals(Bee2SignatureMethod.ECDSA_SHA1)) {
            return new Bee2SignatureMethod.SHA1withECDSA(params);
        } else if (algorithm.equals(Bee2SignatureMethod.ECDSA_SHA224)) {
            return new Bee2SignatureMethod.SHA224withECDSA(params);
        } else if (algorithm.equals(Bee2SignatureMethod.ECDSA_SHA256)) {
            return new Bee2SignatureMethod.SHA256withECDSA(params);
        } else if (algorithm.equals(Bee2SignatureMethod.ECDSA_SHA384)) {
            return new Bee2SignatureMethod.SHA384withECDSA(params);
        } else if (algorithm.equals(Bee2SignatureMethod.ECDSA_SHA512)) {
            return new Bee2SignatureMethod.SHA512withECDSA(params);
        } else if (algorithm.equals(Bee2SignatureMethod.ECDSA_RIPEMD160)) {
            return new Bee2SignatureMethod.RIPEMD160withECDSA(params);
        } else if (algorithm.equals(Bee2SignatureMethod.ED25519)) {
            return new Bee2SignatureMethod.EDDSA_ED25519(params);
        } else if (algorithm.equals(Bee2SignatureMethod.ED448)) {
            return new Bee2SignatureMethod.EDDSA_ED448(params);
        }else {
            throw new NoSuchAlgorithmException("unsupported algorithm");
        }
    }

    @Override
    public Transform newTransform(String algorithm,
        TransformParameterSpec params) throws NoSuchAlgorithmException,
        InvalidAlgorithmParameterException {

        TransformService spi;
        if (getProvider() == null) {
            spi = TransformService.getInstance(algorithm, "DOM");
        } else {
            try {
                spi = TransformService.getInstance(algorithm, "DOM", getProvider());
            } catch (NoSuchAlgorithmException nsae) {
                spi = TransformService.getInstance(algorithm, "DOM");
            }
        }

        spi.init(params);
        return new DOMTransform(spi);
    }

    @Override
    public Transform newTransform(String algorithm,
        XMLStructure params) throws NoSuchAlgorithmException,
        InvalidAlgorithmParameterException {
        TransformService spi;
        if (getProvider() == null) {
            spi = TransformService.getInstance(algorithm, "DOM");
        } else {
            try {
                spi = TransformService.getInstance(algorithm, "DOM", getProvider());
            } catch (NoSuchAlgorithmException nsae) {
                spi = TransformService.getInstance(algorithm, "DOM");
            }
        }

        if (params == null) {
            spi.init(null);
        } else {
            spi.init(params, null);
        }
        return new DOMTransform(spi);
    }

    @Override
    public CanonicalizationMethod newCanonicalizationMethod(String algorithm,
        C14NMethodParameterSpec params) throws NoSuchAlgorithmException,
        InvalidAlgorithmParameterException {
        TransformService spi;
        if (getProvider() == null) {
            spi = TransformService.getInstance(algorithm, "DOM");
        } else {
            try {
                spi = TransformService.getInstance(algorithm, "DOM", getProvider());
            } catch (NoSuchAlgorithmException nsae) {
                spi = TransformService.getInstance(algorithm, "DOM");
            }
        }

        spi.init(params);
        return new DOMCanonicalizationMethod(spi);
    }

    @Override
    public CanonicalizationMethod newCanonicalizationMethod(String algorithm,
        XMLStructure params) throws NoSuchAlgorithmException,
        InvalidAlgorithmParameterException {
        TransformService spi;
        if (getProvider() == null) {
            spi = TransformService.getInstance(algorithm, "DOM");
        } else {
            try {
                spi = TransformService.getInstance(algorithm, "DOM", getProvider());
            } catch (NoSuchAlgorithmException nsae) {
                spi = TransformService.getInstance(algorithm, "DOM");
            }
        }
        if (params == null) {
            spi.init(null);
        } else {
            spi.init(params, null);
        }

        return new DOMCanonicalizationMethod(spi);
    }

    @Override
    public URIDereferencer getURIDereferencer() {
        return Bee2URIDereferencer.INSTANCE;
    }
}