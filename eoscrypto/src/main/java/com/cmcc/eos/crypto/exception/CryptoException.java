package com.cmcc.eos.crypto.exception;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public class CryptoException extends RuntimeException {

    public static final int CRYPTO_ERROR = 1;
    public static final int CERT_HASH_MISMATCH = 2;

    private static final long serialVersionUID = -4194687652165603898L;
    private int code = CRYPTO_ERROR;

    public CryptoException() {
        super();
    }

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(int code, final String message) {
        super(message);
        this.code = code;
    }

    public CryptoException(NoSuchAlgorithmException e) {
        super(e);
    }

    public CryptoException(InvalidKeyException e) {
        super(e);
    }

    public CryptoException(NoSuchProviderException e) {
        super(e);
    }

    public CryptoException(SignatureException e) {
        super(e);
    }

    public CryptoException(FileNotFoundException e) {
        super(e);
    }

    public CryptoException(IOException e) {
        super(e);
    }

    public CryptoException(java.security.cert.CertificateException e) {
        super(e);
    }

    public CryptoException(InvalidKeySpecException e) {
        super(e);
    }

    public CryptoException(OperatorCreationException e) {
        super(e);
    }

    public CryptoException(PKCSException e) {
        super(e);
    }

    public CryptoException(CMSException e) {
        super(e);
    }

    public int getCode() {
        return code;
    }
}
