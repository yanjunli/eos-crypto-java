package com.eos.crypto.util;

import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;

import javax.crypto.Cipher;
import java.security.*;


public class ECCUtil {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    //生成秘钥对
    public static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(256, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    //公钥加密
    public static byte[] publicEncrypt(byte[] content, PublicKey publicKey) throws Exception {
        IESCipher iesCipher = new org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIES();
        iesCipher.engineInit(Cipher.ENCRYPT_MODE,publicKey,new SecureRandom());
        return iesCipher.engineDoFinal(content,0,content.length);
    }

    //私钥解密
    public static byte[] privateDecrypt(byte[] content, PrivateKey privateKey) throws Exception {
        IESCipher iesCipher = new org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIES();
        iesCipher.engineInit(Cipher.DECRYPT_MODE,privateKey,new SecureRandom());
        return iesCipher.engineDoFinal(content,0,content.length);
    }
}