package by.bcrypto.bee2j.provider.xmldsig;

// Source code is decompiled from a .class file using FernFlower decompiler.

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.jcp.xml.dsig.internal.dom.DOMStructure;
import org.apache.jcp.xml.dsig.internal.dom.DOMUtils;

abstract class AbstractBee2SignatureMethod extends DOMStructure implements SignatureMethod {
   AbstractBee2SignatureMethod() {
   }

   abstract boolean verify(Key var1, SignedInfo var2, byte[] var3, XMLValidateContext var4) throws InvalidKeyException, SignatureException, XMLSignatureException;

   abstract byte[] sign(Key var1, SignedInfo var2, XMLSignContext var3) throws InvalidKeyException, XMLSignatureException;

   abstract String getJCAAlgorithm();

   //abstract Type getAlgorithmType();

   public void marshal(Node parent, String dsPrefix, DOMCryptoContext context) throws MarshalException {
      Document ownerDoc = DOMUtils.getOwnerDocument(parent);
      Element smElem = DOMUtils.createElement(ownerDoc, "SignatureMethod", "http://www.w3.org/2000/09/xmldsig#", dsPrefix);
      DOMUtils.setAttribute(smElem, "Algorithm", this.getAlgorithm());
      if (this.getParameterSpec() != null) {
         this.marshalParams(smElem, dsPrefix);
      }

      parent.appendChild(smElem);
   }

   void marshalParams(Element parent, String paramsPrefix) throws MarshalException {
      throw new MarshalException("no parameters should be specified for the " + this.getAlgorithm() + " SignatureMethod algorithm");
   }

   SignatureMethodParameterSpec unmarshalParams(Element paramsElem) throws MarshalException {
      throw new MarshalException("no parameters should be specified for the " + this.getAlgorithm() + " SignatureMethod algorithm");
   }

   void checkParams(SignatureMethodParameterSpec params) throws InvalidAlgorithmParameterException {
      if (params != null) {
         throw new InvalidAlgorithmParameterException("no parameters should be specified for the " + this.getAlgorithm() + " SignatureMethod algorithm");
      }
   }

   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (!(o instanceof SignatureMethod)) {
         return false;
      } else {
         SignatureMethod osm = (SignatureMethod)o;
         return this.getAlgorithm().equals(osm.getAlgorithm()) && this.paramsEqual(osm.getParameterSpec());
      }
   }

   public int hashCode() {
      int result = 17;
      result = 31 * result + this.getAlgorithm().hashCode();
      AlgorithmParameterSpec spec = this.getParameterSpec();
      if (spec != null) {
         result = 31 * result + spec.hashCode();
      }

      return result;
   }

   boolean paramsEqual(AlgorithmParameterSpec spec) {
      return this.getParameterSpec() == spec;
   }
}

