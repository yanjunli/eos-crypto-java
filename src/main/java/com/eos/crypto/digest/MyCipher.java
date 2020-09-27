package com.eos.crypto.digest;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import java.security.Provider;

public class MyCipher extends Cipher {

    protected MyCipher(CipherSpi cipherSpi, Provider provider, String s) {
        super(cipherSpi, provider, s);
    }
}
