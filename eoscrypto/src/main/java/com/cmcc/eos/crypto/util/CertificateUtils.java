package com.cmcc.eos.crypto.util;

import com.cmcc.eos.crypto.exception.CryptoException;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;

public class CertificateUtils {

    public static final String SHA256 = "SHA256";

    private static final String ECDSA_SHA256 = "SHA256withECDSA";

    private static final String BC_PROVIDER = "BC";


    public static X509Certificate generateX509Certificate(PKCS10CertificationRequest certReq,
                                                          PrivateKey caPrivateKey, X509Certificate caCertificate, int validityTimeout,
                                                          boolean basicConstraints) {

        return generateX509Certificate(certReq, caPrivateKey,
                X500Name.getInstance(caCertificate.getSubjectX500Principal().getEncoded()),
                validityTimeout, basicConstraints);
    }

    public static X509Certificate generateX509Certificate(PKCS10CertificationRequest certReq,
                                                          PrivateKey caPrivateKey, X500Name issuer, int validityTimeout,
                                                          boolean basicConstraints) {

        // set validity for the given number of minutes from now

        Date notBefore = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(notBefore);
        cal.add(Calendar.MINUTE, validityTimeout);
        Date notAfter = cal.getTime();

        // Generate self-signed certificate

        X509Certificate cert;
        try {
            JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = new JcaPKCS10CertificationRequest(certReq);
            PublicKey publicKey = jcaPKCS10CertificationRequest.getPublicKey();

            X509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
                    issuer, BigInteger.valueOf(System.currentTimeMillis()),
                    notBefore, notAfter, certReq.getSubject(), publicKey)
                    .addExtension(Extension.basicConstraints, false,
                            new BasicConstraints(basicConstraints))
                    .addExtension(Extension.keyUsage, true,
                            new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment))
                    .addExtension(Extension.extendedKeyUsage, true,
                            new ExtendedKeyUsage(new KeyPurposeId[]{ KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth }));

            // see if we have the dns/rfc822/ip address extensions specified in the csr

            ArrayList<GeneralName> altNames = new ArrayList<>();
            Attribute[] certAttributes = jcaPKCS10CertificationRequest.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            if (certAttributes != null && certAttributes.length > 0) {
                for (Attribute attribute : certAttributes) {
                    Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
                    GeneralNames gns = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
                    ///CLOVER:OFF
                    if (gns == null) {
                        continue;
                    }
                    ///CLOVER:ON
                    GeneralName[] names = gns.getNames();
                    for (GeneralName name : names) {
                        switch (name.getTagNo()) {
                            case GeneralName.dNSName:
                            case GeneralName.iPAddress:
                            case GeneralName.rfc822Name:
                            case GeneralName.uniformResourceIdentifier:
                                altNames.add(name);
                                break;
                        }
                    }
                }
                if (!altNames.isEmpty()) {
                    caBuilder.addExtension(Extension.subjectAlternativeName, false,
                            new GeneralNames(altNames.toArray(new GeneralName[0])));
                }
            }

            String signatureAlgorithm = getSignatureAlgorithm(caPrivateKey.getAlgorithm(), SHA256);
            ContentSigner caSigner = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BC_PROVIDER).build(caPrivateKey);

            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BC_PROVIDER);
            cert = converter.getCertificate(caBuilder.build(caSigner));
            ///CLOVER:OFF
        } catch (CertificateException ex) {
            System.err.println("generateX509Certificate: Caught CryptoException when generating certificate: "
                    + ex.getMessage());
            throw new CryptoException(ex);
        } catch (OperatorCreationException ex) {
            System.err.println("generateX509Certificate: Caught OperatorCreationException when creating JcaContentSignerBuilder: "
                    + ex.getMessage());
            throw new CryptoException(ex);
        } catch (InvalidKeyException ex) {
            System.err.println("generateX509Certificate: Caught InvalidKeySpecException, invalid key spec is being used: "
                    + ex.getMessage());
            throw new CryptoException(ex);
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("generateX509Certificate: Caught NoSuchAlgorithmException, check to make sure the algorithm is supported by the provider: "
                    + ex.getMessage());
            throw new CryptoException(ex);
        } catch (Exception ex) {
            System.err.println("generateX509Certificate: unable to generate X509 Certificate: " + ex.getMessage());
            throw new CryptoException("Unable to generate X509 Certificate");
        }
        ///CLOVER:ON
        return cert;
    }

    static String getSignatureAlgorithm(String keyAlgorithm) throws NoSuchAlgorithmException {
        return getSignatureAlgorithm(keyAlgorithm, SHA256);
    }

    static String getSignatureAlgorithm(String keyAlgorithm, String digestAlgorithm) throws NoSuchAlgorithmException {

        String signatureAlgorithm = null;
        if (SHA256.equals(digestAlgorithm)) {
            signatureAlgorithm = ECDSA_SHA256;
        }
        if (signatureAlgorithm == null) {
            throw new NoSuchAlgorithmException("getSignatureAlgorithm: Unknown key algorithm: " + keyAlgorithm
                    + " digest algorithm: " + digestAlgorithm);
        }

        System.out.println("Signature Algorithm: " + signatureAlgorithm);

        return signatureAlgorithm;
    }
}
