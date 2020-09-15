package com.eos.crypto.util;

import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import java.security.*;


public class ECCUtil {

    private static byte[] derivation = Hex.decode("202122232425262728292a2b2c2d2e2f");
    private static byte[] encoding   = Hex.decode("303132333435363738393a3b3c3d3e3f");
    private static byte[] nonce = Hex.decode("000102030405060708090a0b0c0d0e0f");

    private static ThreadLocal<SecureRandom> local = ThreadLocal.withInitial(()->new SecureRandom());

    private static IESParameterSpec iesParameterSpec = new IESParameterSpec(derivation, encoding, 128, 128, nonce);

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
        IESCipher.ECIESwithAESCBC iesCipher = new IESCipher.ECIESwithAESCBC();
        iesCipher.engineInit(Cipher.ENCRYPT_MODE,
                publicKey,
                iesParameterSpec,
                local.get());
        return iesCipher.engineDoFinal(content,0,content.length);
    }

    //私钥解密
    public static byte[] privateDecrypt(byte[] content, PrivateKey privateKey) throws Exception {
        IESCipher iesCipher = new org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIESwithAESCBC();
        iesCipher.engineInit(Cipher.DECRYPT_MODE,
                privateKey,
                iesParameterSpec,
                local.get());
        return iesCipher.engineDoFinal(content,0,content.length);
    }
}