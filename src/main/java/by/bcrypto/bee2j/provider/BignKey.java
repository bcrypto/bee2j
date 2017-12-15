package by.bcrypto.bee2j.provider;

import by.bcrypto.bee2j.BignParams;
import java.math.BigInteger;
import java.security.*;

public abstract class BignKey implements Key{
    public byte[] bytes;

    public BignParams bignParams;

    public byte[] getBytes(){
        return bytes;
    }

    public void setBytes(byte[] bytes) {
        this.bytes = bytes;
    }

    public String getAlgorithm() {
        return "Bign";
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] getEncoded() {
        //DEROctetString der = new DEROctetString(bytes);
        //ByteOutputStream os = new ByteOutputStream();

        //DEROutputStream derStream = new DEROutputStream(os);

        //DEROctetString.encode(derStream, );

  /*      try {
            ASN1Encodable[] asn_sec = {new AlgorithmIdentifier("1.2.112.0.2.0.34.101.45.3.1"), new DERBitString(bytes)};
            ASN1Sequence sec = new DERSequence(asn_sec);

            return sec.getEncoded();
        } catch (IOException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            return null;
        }
        */
        return bytes;
    }

    public BignKey() {
        super();
    }

    public BignKey(byte[] bytes) {
        super();
        setBytes(bytes);
    }

    @Override
    public boolean equals(Object obj) {
        return new BigInteger(bytes).equals(new BigInteger(((BignKey)obj).bytes));
    }
}

