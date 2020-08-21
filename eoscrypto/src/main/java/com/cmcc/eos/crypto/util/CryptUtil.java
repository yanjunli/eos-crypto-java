/*
 * Copyright (c) 2017-2018 PlayerOne.
 *
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.cmcc.eos.crypto.util;

import com.cmcc.eos.crypto.digest.Sha256;
import com.cmcc.eos.crypto.ec.EcPoint;
import com.cmcc.eos.crypto.ec.EosPrivateKey;
import com.cmcc.eos.crypto.ec.EosPublicKey;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.math.BigInteger;


/**
d */

public class CryptUtil {

//    private static final String ALGORITHM = "AES/GCM/NoPadding";

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    /**
     *  unique 64 bit unsigned number string. Being time based,this is careful to never choose the same nonce twice.
     *  This value could be recorded in the blockchain for a long time.
     * @return
     */
    public static String uniqueNonce(){
        MTRandom mtRandom=new MTRandom();
        byte[] b = new byte[2];
        mtRandom.nextBytes(b);
        int uniqueNonceEntropy = b[0] << 8 | b[1];
        BigInteger now = BigInteger.valueOf(System.currentTimeMillis());
        int entropy = ++uniqueNonceEntropy % 0xFFFF;
        return now.shiftLeft(16).or(BigInteger.valueOf(entropy)).toString(10);
    }

    public static byte[] getSecret(EosPrivateKey privateKey, EosPublicKey publickey){
        EcPoint ecPoint = publickey.getEcPoint();
        EcPoint newPoint = ecPoint.multiply(privateKey.getAsBigInteger());
        byte[] s = newPoint.getX().toBigInteger().toByteArray();
        return Sha256.from(s).getBytes();
    }

    public static byte[] encrypt(EosPrivateKey privaetkey,EosPublicKey publickey1,EosPublicKey publickey2,byte[] nonce,byte[] data) throws InvalidCipherTextException {
        byte[] key = getSecret(privaetkey,publickey1);
        byte[] key2 = getSecret(privaetkey,publickey2);
        byte[] key3 = new byte[key.length+key2.length];
        System.arraycopy(key,0,key3,0,key.length);
        System.arraycopy(key2,0,key3,key.length,key2.length);
        return aesEncrypt(key3,data,nonce);
    }

    /**
     * 双向验证 加密方法
     * @param privaetkey
     * @param publickey
     * @param nonce
     * @param data
     * @return
     * @throws InvalidCipherTextException
     */
    public static byte[] encrypt(EosPrivateKey privaetkey,EosPublicKey publickey,byte[] nonce,byte[] data) throws InvalidCipherTextException {
        byte[] key = getSecret(privaetkey,publickey);
        return aesEncrypt(key,data,nonce);
    }

    /**
     *  双向验证，解密方法
     * @param privaetkey
     * @param publickey
     * @param nonce
     * @param data
     * @return
     * @throws InvalidCipherTextException
     */
    public static byte[] decrypt(EosPrivateKey privaetkey,EosPublicKey publickey,byte[] nonce,byte[] data) throws InvalidCipherTextException {
        byte[] key = getSecret(privaetkey,publickey);
        return aesDecrypt(key,data,nonce);
    }


    /**
     *  AES 加密
     * @param key     密钥key
     * @param data   待加密数据
     * @return
     * @throws InvalidCipherTextException
     */
    public static byte[] aesEncryptWithNOIV( byte[] key, byte[] data) throws InvalidCipherTextException {
        return crypto(key,data,true);
    }

    /**
     *  AES 解密
     * @param key   密钥key
     * @param data  待解密数据
     * @return
     * @throws InvalidCipherTextException
     */
    public static byte[] aesDecryptWithNOIV( byte[] key, byte[] data) throws InvalidCipherTextException {
        return crypto(key,data,false);
    }


    /**
     *  AES 加密
     * @param key     密钥key
     * @param data   待加密数据
     * @param iv     初始化向量
     * @return
     * @throws InvalidCipherTextException
     */
    public static byte[] aesEncrypt( byte[] key, byte[] data,byte[] iv) throws InvalidCipherTextException {
        return crypto(key,data,iv,true);
    }

    /**
     *  AES 解密
     * @param key   密钥key
     * @param data  待解密数据
     * @param iv    初始化向量
     * @return
     * @throws InvalidCipherTextException
     */
    public static byte[] aesDecrypt( byte[] key, byte[] data,  byte[] iv) throws InvalidCipherTextException {
        return crypto(key,data,iv,false);
    }

    private static byte[] crypto(byte[] key, byte[] data,boolean forEncryption) throws InvalidCipherTextException{
        byte[] encrypted = null;
        KeyParameter keyParam = new KeyParameter(key);
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()),new PKCS7Padding());
        cipher.reset();
        cipher.init(forEncryption,keyParam);
        encrypted = new byte[cipher.getOutputSize(data.length)];
        int len = cipher.processBytes(data,0,data.length,encrypted,0);
        cipher.doFinal(encrypted,len);

        return encrypted;
    }


    private static byte[] crypto(byte[] key, byte[] data,  byte[] iv,boolean forEncryption) throws InvalidCipherTextException{
        byte[] encrypted = null;

        if ( iv.length > 16 ) {
            iv = Arrays.copyOf(iv,16);
        }

        KeyParameter keyParam = new KeyParameter(key);
        CipherParameters params = new ParametersWithIV(keyParam,iv);
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()),new PKCS7Padding());
        cipher.reset();
        cipher.init(forEncryption,params);
        encrypted = new byte[cipher.getOutputSize(data.length)];
        int len = cipher.processBytes(data,0,data.length,encrypted,0);
        cipher.doFinal(encrypted,len);

        return encrypted;
    }
}
