package by.bcrypto.bee2j.provider.pki;

import java.io.InputStream;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collection;

public class BignCertificateFactory extends CertificateFactorySpi {

    private final CertificateFactory certificateFactory;

    public BignCertificateFactory() throws CertificateException {
        certificateFactory = CertificateFactory.getInstance("X.509");
    }

    @Override
    public Certificate engineGenerateCertificate(InputStream inStream) throws CertificateException {
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inStream);

        return new BignCertificate(certificate);
    }

    @Override
    public Collection<? extends Certificate> engineGenerateCertificates(InputStream inStream) throws CertificateException {
        Collection<BignCertificate> bignCertificates = new ArrayList<>();
        var certificates = certificateFactory.generateCertificates(inStream);

        for (Certificate certificate : certificates) {
            bignCertificates.add(new BignCertificate((X509Certificate) certificate));
        }

        return bignCertificates;
    }

    @Override
    public CRL engineGenerateCRL(InputStream inStream) throws CRLException {
        return certificateFactory.generateCRL(inStream);
    }

    @Override
    public Collection<? extends CRL> engineGenerateCRLs(InputStream inStream) throws CRLException {
        return certificateFactory.generateCRLs(inStream);
    }
}
