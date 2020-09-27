package com.eos.crypto.util;

import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.security.Key;
import java.security.cert.X509Certificate;

public class PEMUtils {

    private PEMUtils() {
    }

    public static byte[] toPEM(PKCS10CertificationRequest csr) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8))) {
            pemWriter.writeObject(new JcaMiscPEMGenerator(csr));
            pemWriter.flush();
        }
        return os.toByteArray();
    }

    public static String toPEM(X509Certificate certificate) throws IOException {
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        try {
            pemWriter.writeObject(new JcaMiscPEMGenerator(certificate));
            pemWriter.flush();
        } finally {
            pemWriter.close();
        }
        return stringWriter.toString();
    }

    public static String toPEM(Key key) throws IOException {
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        try {
            pemWriter.writeObject(new JcaMiscPEMGenerator(key));
            pemWriter.flush();
        } finally {
            pemWriter.close();
        }
        return stringWriter.toString();
    }
}
