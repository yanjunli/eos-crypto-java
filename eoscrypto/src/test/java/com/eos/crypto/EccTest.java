package com.eos.crypto;

import com.eos.crypto.digest.Sha256;
import com.eos.crypto.ec.EcDsa;
import com.eos.crypto.ec.EcSignature;
import com.eos.crypto.ec.EosPrivateKey;
import com.eos.crypto.ec.EosPublicKey;
import com.eos.crypto.types.EosByteWriter;
import com.eos.crypto.util.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * 数据加解密测试
 *  本测试类 基于ecc+aes  演示 以下两个应用场景。
 *   1. 基于信封的 加解密示例
 *   2. 双向验证的 加解密示例
 */
public class EccTest {

    static{
        try{
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public class TypeChainId {
        private Sha256 mId;

        public TypeChainId() {
            mId = Sha256.ZERO_HASH;
        }

        public TypeChainId(String sha256_string) {
            mId = new Sha256(HexUtils.toBytes(sha256_string));
        }

        public byte[] getBytes() {
            return mId.getBytes();
        }
    }

    public Sha256 getDigestForSignature(TypeChainId chainId,String hexData) {
        EosByteWriter writer = new EosByteWriter(512);

        // data layout to sign :
        // [ {chainId}, {Transaction( parent class )}, {hash of context_free_data only when exists ]


        writer.putBytes(chainId.getBytes());
        writer.putBytes(HexUtils.toBytes(hexData));

        writer.putBytes( Sha256.ZERO_HASH.getBytes());
        return Sha256.from(writer.toBytes());
    }

    /**
     *  1. 基于数字信封的 加解密示例
     * @throws Exception
     */
    @Test
    public void cryto1() throws Exception {

        /**
         *
         * sender
         *
         * EOS8g1u3ktAGHs4QsVp9aeaWNebFLtprQHwpaSjegx6iEuoTNhjXU
         * 5KTZYCDdcfNrmEpcf97SJBCtToZjYHjHm8tqTWvzUbsUJgkxcfk
         *
         * receiver 平台公私钥对
         *
         * EOS7ez2gagfoXw9XdW3kRx3EsCoWvupGR6u6ZJhFPEe9Q12V8JgUL
         * 5JUrqxYcssR9LLVtWDeQcc9HCX4FEqBG7d9GW6t7mvmB1rUuZr9
         *
         * receiver 省侧公私钥对
         * EOS5WMHqw6jDDBPBm7JXTHemAwtSo2tp93pRysJMRhiT1zUYb24vL
         * 5HrcVeuHHNwHsivrMoJ9XvU6EM7Q2wQ2ECiy8GeoiuamhNiSuZq
         */

        // 1.  调用钱包获取 发送方私钥
        String senderPrivateKey =  "5KTZYCDdcfNrmEpcf97SJBCtToZjYHjHm8tqTWvzUbsUJgkxcfk";
        EosPrivateKey senderECPrivateKey = new EosPrivateKey(senderPrivateKey);
//        EosPublicKey senderECPublicKey = new EosPublicKey(senderPublicKey);
        // 2.  根据私钥 生成公钥。 或者直接根据公钥 调用钱包获取私钥。 都可以，看具体业务需求
        EosPublicKey senderECPublicKey = senderECPrivateKey.getPublicKey();

        String senderPublicKey = senderECPublicKey.toString();
        /**
         * 调用钱包获取 接收方私钥   获取公私钥方式 根据业务需求确定。
         *  1. 可以根据公钥，从钱包里获取私钥
         *  2. 也可以直接从钱包里取出私钥，反向生成公钥
         */
        String receiverPrivateKey = "5JUrqxYcssR9LLVtWDeQcc9HCX4FEqBG7d9GW6t7mvmB1rUuZr9";
        EosPrivateKey receiverECPrivateKey = new EosPrivateKey(receiverPrivateKey);

        EosPublicKey receiverECPublicKey = receiverECPrivateKey.getPublicKey();

        /**
         * 生成对称密钥
         */
        byte[] nonce = new byte[16];
        MTRandom random=new MTRandom();
        random.nextBytes(nonce);

        // 待加密 数据
        byte[] params = "{\"age\": 1,\"汉字\":\"为初始化向量，可以使用固定值，\"，\"12345\":\"24qqwazzxdtttdxkaskjewuizckczxnlsdosasda4!!!@#$$%^&&*(()(^#\"}".getBytes("utf8");

        System.out.println("加密前原始数据： " + new String(params,"utf8"));

        // 发起方使用对称密钥，对原始数据进行加密
        byte[] encryptedData = null;
        try {
            encryptedData = CryptUtil.aesEncryptWithNOIV(nonce,params);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            System.out.println("  do something!!!!");
        }

        System.out.println("加密后数据： " + HexUtils.toHex(encryptedData));


        System.out.println("加密前对称密钥： " + HexUtils.toHex(nonce));

        // 发起方使用 接收方公钥，对对称密钥进行加密
        byte[] encryptedKey = null;
        try {
            encryptedKey = ECCUtil.publicEncrypt(nonce,receiverECPublicKey.getECPublicKey());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("  do something!!!!");
        }

        System.out.println("加密后对称密钥： " + HexUtils.toHex(encryptedKey));

        // 将对称密钥加密后的数据，密文组装后，进行网络传输。
        // 组装 demo
        /**
         *    4 byte                       |      encryptedKey                 |       4 byte              | encryptedData
         *    对称密钥加密后的数据长度      |      ECC 加密后的对称秘钥           |       密文数据长度         | AES 加密后的密文
         */

        ByteBuffer bytebuffer = ByteBuffer.allocate( 4 + encryptedKey.length + 4 +encryptedData.length);
        bytebuffer.putInt(encryptedKey.length);
        bytebuffer.put(encryptedKey);
        bytebuffer.putInt(encryptedData.length);
        bytebuffer.put(encryptedData);

//        String base58encode = Base58.encode(bytebuffer.array());
//        System.out.println("base58 编码后的:   " + base58encode);

        // 进行 16 进制编码
        String hexencode = HexUtils.toHex(bytebuffer.array());

        System.out.println(" 将数字信封和密文组装后的报文 16进制格式：" + hexencode);

        System.out.println("发送方数据加密完成，可以将数据发送出去 ");

        /**
         *****************************************************  以下为接收方 代码  *************************************
         */

//        byte[] base58decode = Base58.decode(hexencode);

        byte[] hexdecode = HexUtils.toBytes(hexencode);
        ByteBuffer receiveBuffer = ByteBuffer.wrap(hexdecode);

        // 获取到对称秘钥长度
        int receivedEncryptedKeyLength = receiveBuffer.getInt();
        // 加密后的对称密钥key
        byte[] receivedEncryptKey = new byte[receivedEncryptedKeyLength];
        receiveBuffer.get(receivedEncryptKey,0,receivedEncryptedKeyLength);

        System.out.println(" 接收到的 加密后的对称密钥 ：" + HexUtils.toHex(receivedEncryptKey));
        // 获取到的 密文的长度
        int contextLength = receiveBuffer.getInt();
        // 密文
        byte[] receivedEncryptContext = new byte[contextLength];
        receiveBuffer.get(receivedEncryptContext,0,contextLength);

        System.out.println(" 接收到的 密文：" + HexUtils.toHex(receivedEncryptContext));


        // 使用接收方私钥，解密对称密钥
        byte[] receiveddecryptKey = null;
        try {
            receiveddecryptKey = ECCUtil.privateDecrypt(receivedEncryptKey,receiverECPrivateKey.getECPrivateKey());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("  do something!!!!");
        }

        System.out.println(" 解密后的对称密钥 ：" + HexUtils.toHex(receiveddecryptKey));

        // 使用对称密钥，对密文进行解密

        try {
            byte[] plainText = CryptUtil.aesDecryptWithNOIV(receiveddecryptKey,receivedEncryptContext);
            // 解密后数据
            System.out.println("解密后数据 :  "+new String(plainText, "utf8"));
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            System.out.println("  do something!!!!");
        }
    }

    /**
     *  ecc + aes  双向验证代码示例
     * @throws UnsupportedEncodingException
     */
    @Test
    public  void crypto2() throws Exception {

        /**
         *
         * sender    发送方公私钥对
         *
         * EOS8g1u3ktAGHs4QsVp9aeaWNebFLtprQHwpaSjegx6iEuoTNhjXU
         * 5KTZYCDdcfNrmEpcf97SJBCtToZjYHjHm8tqTWvzUbsUJgkxcfk
         *
         * receiver  接收方公私钥对
         *
         * EOS7ez2gagfoXw9XdW3kRx3EsCoWvupGR6u6ZJhFPEe9Q12V8JgUL
         * 5JUrqxYcssR9LLVtWDeQcc9HCX4FEqBG7d9GW6t7mvmB1rUuZr9
         *
         * receiver  接收方公私钥对
         * EOS5WMHqw6jDDBPBm7JXTHemAwtSo2tp93pRysJMRhiT1zUYb24vL
         * 5HrcVeuHHNwHsivrMoJ9XvU6EM7Q2wQ2ECiy8GeoiuamhNiSuZq
         */

        // 1.  调用钱包获取 发送方私钥
        String senderPrivateKey =  "5KTZYCDdcfNrmEpcf97SJBCtToZjYHjHm8tqTWvzUbsUJgkxcfk";
        EosPrivateKey senderECPrivateKey = new EosPrivateKey(senderPrivateKey);
//        EosPublicKey senderECPublicKey = new EosPublicKey(senderPublicKey);
        // 2.  根据私钥 生成公钥。 或者直接根据公钥 调用钱包获取私钥。 都可以，看具体业务需求
        EosPublicKey senderECPublicKey = senderECPrivateKey.getPublicKey();

        String senderPublicKey = senderECPublicKey.toString();
        /**
         * 调用钱包获取 接收方私钥   获取公私钥方式 根据业务需求确定。
         *  1. 可以根据公钥，从钱包里获取私钥
         *  2. 也可以直接从钱包里取出私钥，反向生成公钥
         */
        String receiverPrivateKey = "5JUrqxYcssR9LLVtWDeQcc9HCX4FEqBG7d9GW6t7mvmB1rUuZr9";
        EosPrivateKey receiverECPrivateKey = new EosPrivateKey(receiverPrivateKey);
        EosPublicKey receiverECPublicKey = receiverECPrivateKey.getPublicKey();
//        String receiverPublicKey =  "EOS7ez2gagfoXw9XdW3kRx3EsCoWvupGR6u6ZJhFPEe9Q12V8JgUL";
        String receiverPublicKey = receiverECPublicKey.toString();

        /**
         * 使用 发送者方私钥 和接收方公钥，生成 aes key, 对数据进行加密
         * nonce  为初始化向量，可以使用固定值，
         *                      也可以使用随机值，并使用私有协议。根据业务需求选择。
         *  请参考技术规范中约定的格式
         */
        byte[] nonce = new byte[16];
        MTRandom random=new MTRandom();
        random.nextBytes(nonce);

        // 待加密 数据
        byte[] params = "{\"age\": 1,\"12345\":\"24qqwazzxdtttdxkaskjewuizckczxnlsdosasda4!!!@#$$%^&&*(()(^#\"}".getBytes("utf8");


        System.out.println("原始加密数据： " + new String(params,"utf8"));

        byte[] encrypted = new byte[0];
        try {
            encrypted = CryptUtil.encrypt(senderECPrivateKey,receiverECPublicKey,nonce,params);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            System.out.println("  do something!!!!");
        }

        System.out.println("加密后数据： " + HexUtils.toHex(encrypted));


        System.out.println("base58 编码后数据:   " + Base58.encode(encrypted));

        try {
            byte[] plainText = CryptUtil.decrypt(receiverECPrivateKey,senderECPublicKey,nonce,encrypted);
            // 解密后数据
            System.out.println("解密后数据 :  "+new String(plainText, "utf8"));
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            System.out.println("  do something!!!!");
        }
    }

    @Test
    public void verifySignature() throws Exception {
        /**
         *  16 进制 交易数据
         */
        String hexData = "6a3f0e5f210a14b478050000000001603463937a4c8f440000b82a5d5a91d401809fd18c4dea8f4400000020476d964aa701809fd18c4dea8f440f495ab51e9cb44908424f53533130303008554d43503130303004554d43501f3533314249503242333235323032303034313531363238323231353336363908ab91465f12000006017560c95d040000007560c95d0400000000000000000000000100000000000000080006323130303130c818f4515f12000040035df1481b000006363938303237082d4359313647424e0200000000000000000000000000";

        System.out.println(new String(HexUtils.toBytesReversed(hexData)));

        /**
         *  eos 签名
         */
        String signStr = "SIG_K1_K1Pgvc9jXrCbPXx23zGugEfhxcGXoCSJjFEzFQj2HoFie18qnizWzQGssQezmS8PZ9fkKci3k8PGM2MQpJvuXtRZtd4oCD";
        EcSignature ecSignature = new EcSignature(signStr);
        Sha256 curData = getDigestForSignature(new TypeChainId("4a2fb7b7aacce5ea952dc96fbac6ed648efc08c1e1577882f3f33c82da248d64"),hexData);
        /**
         *  验证签名
         */

        EosPublicKey eosPublicKey =  EcDsa.recoverPubKey(curData.getBytes(), ecSignature);

        System.out.println(" 验签结果"+eosPublicKey.toString().equals("EOS4wTJSTd29mZ4MNPZ2y4q2PtrimVpHLwHg8U4XMdzSBLa4BeYmN"));


        ecSignature = new EcSignature("SIG_K1_KAbKETVxar8gWsnQ6im6yFVm53GBAVxskhW9eud8Beiiogpv5X4NTTnL2E2eJUj4tS6PfsP9yRRCQXjoxoS7mvcFXHbGVL");
        eosPublicKey =  EcDsa.recoverPubKey(curData.getBytes(), ecSignature);

        System.out.println(" 验签结果"+eosPublicKey.toString().equals("EOS5G4bcND3mCGwE7SPVVXoDykEV9wQCH69d41J49mfqFAPuseS9K"));
    }


    /**
     * 根据 EOS 交易数据 恢复 公钥 示例
     */
    @Test
    public void crypto3(){
        /**
         *  16 进制 交易数据
         */
        String hexData = "6a3f0e5f210a14b478050000000001603463937a4c8f440000b82a5d5a91d401809fd18c4dea8f4400000020476d964aa701809fd18c4dea8f440f495ab51e9cb44908424f53533130303008554d43503130303004554d43501f3533314249503242333235323032303034313531363238323231353336363908ab91465f12000006017560c95d040000007560c95d0400000000000000000000000100000000000000080006323130303130c818f4515f12000040035df1481b000006363938303237082d4359313647424e0200000000000000000000000000";
        /**
         *  eos 签名
         */
        String signStr = "SIG_K1_K1Pgvc9jXrCbPXx23zGugEfhxcGXoCSJjFEzFQj2HoFie18qnizWzQGssQezmS8PZ9fkKci3k8PGM2MQpJvuXtRZtd4oCD";
        EcSignature ecSignature = new EcSignature(signStr);
        Sha256 curData = getDigestForSignature(new TypeChainId("4a2fb7b7aacce5ea952dc96fbac6ed648efc08c1e1577882f3f33c82da248d64"),hexData);
        /**
         *  恢复公钥
         */
        EosPublicKey eosPublicKey =  EcDsa.recoverPubKey(curData.getBytes(), ecSignature);

        System.out.println("publicKey: " + eosPublicKey.toString());
        /**
         *  验证 恢复出来的公钥，与原公钥是否相同
         */
        Assert.assertEquals("EOS4wTJSTd29mZ4MNPZ2y4q2PtrimVpHLwHg8U4XMdzSBLa4BeYmN",eosPublicKey.toString());
    }

    /**
     *  根据签名 恢复 EOS 公钥
     */
    @Test
    public void crypto4() throws Exception {

        EosPrivateKey privateKey = new EosPrivateKey("5KTZYCDdcfNrmEpcf97SJBCtToZjYHjHm8tqTWvzUbsUJgkxcfk");

        System.out.println(privateKey.getPublicKey().toString());

        Sha256 hashData = Sha256.from("hi,I'm hello!!!".getBytes());

        System.out.println(HexUtils.toHex(hashData.getBytes()));

        System.out.println(new String(hashData.getBytes()));

        EcSignature signature = privateKey.sign(hashData);
        /**
         * 恢复公钥
         */
        EosPublicKey testPublicKey = EcDsa.recoverPubKey(hashData.getBytes(),signature);

        System.out.println(testPublicKey.toString());

        /**
         * 验证 恢复的公钥与原公钥是否相同
         */
        Assert.assertEquals(privateKey.getPublicKey().toString(),testPublicKey.toString());
    }

    /**
     *  公钥加密私钥解密示例
     * @throws Exception
     */
    @Test
    public void eccTest() throws Exception {


//        /**
//         * 公钥
//         */
//        EosPublicKey eosPublicKey = new EosPublicKey("EOS8g1u3ktAGHs4QsVp9aeaWNebFLtprQHwpaSjegx6iEuoTNhjXU");
//        ECPublicKey  ecPublicKey = cmbaasPublicKey.getECPublicKey();


        String privateKey =  "5KTZYCDdcfNrmEpcf97SJBCtToZjYHjHm8tqTWvzUbsUJgkxcfk";
        EosPrivateKey eosPrivateKey = new EosPrivateKey(privateKey);
        EosPublicKey  eosPublicKey = eosPrivateKey.getPublicKey();
        // 转换成 EC privatekey
        ECPrivateKey ecPrivateKey = eosPrivateKey.getECPrivateKey();
        ECPublicKey ecPublicKey = eosPublicKey.getECPublicKey();


        byte[] plaindata = "{\"age\": 1,\"12345\":\"24qqwazzxdtttdxkaskjewuizckczxnlsdosasda4!!!@#$$%^&&*(()(^#\"}".getBytes("utf8");

        System.out.println("明文：" + new String(plaindata));

        byte[] encryptdata = ECCUtil.publicEncrypt(plaindata,ecPublicKey);

        // 将加密密文，经过16进制编码后, 进行网络传输。
        String hexData = HexUtils.toHex(encryptdata);

        System.out.println("加密后密文：" + hexData);

        //  下载方，从网络接收到数据后，先进行16进制解码，再进行解密，得到明文
        plaindata = ECCUtil.privateDecrypt(HexUtils.toBytes(hexData),ecPrivateKey);

        System.out.println("解密后原文: "+ new String(plaindata));
    }

    @Test
    public void generateCSR() throws Exception {

        String senderPrivateKey =  "5KTZYCDdcfNrmEpcf97SJBCtToZjYHjHm8tqTWvzUbsUJgkxcfk";
        EosPrivateKey senderECPrivateKey = new EosPrivateKey(senderPrivateKey);
        // 转换成 EC privatekey
        ECPrivateKey ecPrivateKey = senderECPrivateKey.getECPrivateKey();

        System.out.println(ecPrivateKey.toString());

        EosPublicKey senderECPublicKey = senderECPrivateKey.getPublicKey();
        // 转换成 EC publickey
        ECPublicKey ecPublicKey = senderECPublicKey.getECPublicKey();

        System.out.println(ecPublicKey.toString());

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

        extensionsGenerator
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        extensionsGenerator.addExtension(
                Extension.extendedKeyUsage,
                true,
                new ExtendedKeyUsage(
                        new KeyPurposeId[]{
                                //用于客户端和服务端认证
                                KeyPurposeId.id_kp_clientAuth,
                                KeyPurposeId.id_kp_serverAuth,
                        }
                ));

        //添加扩展信息
        extensionsGenerator.addExtension(
                Extension.subjectAlternativeName,
                true,
                getSANs()
        );



        //生成 csr
        PKCS10CertificationRequest csr =
                new JcaPKCS10CertificationRequestBuilder(
                        getSubject(),
                        ecPublicKey)
                        .addAttribute(
                                PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                                extensionsGenerator.generate()
                        )
                        .build(
                                new JcaContentSignerBuilder("SHA256withECDSA")
                                        .build(ecPrivateKey)
                        );

        csr = new PKCS10CertificationRequest(csr.getEncoded());

        StringWriter string = new StringWriter();
        PemWriter pemWriter = new PemWriter(string);

        PemObjectGenerator objGen = new MiscPEMGenerator(csr);
        pemWriter.writeObject(objGen);
        pemWriter.close();

        System.out.println(PEMUtils.toPEM(ecPrivateKey));
        System.out.println(string.toString());
        System.out.println(PEMUtils.toPEM(ecPublicKey));


        X500Name issuer = X500Name.getInstance(csr.getSubject().getEncoded());

        X509Certificate caCertificate = CertificateUtils.generateX509Certificate(csr,ecPrivateKey,issuer,30 * 24 * 60 * 12 * 100,true);

        System.out.println("==========================");

        System.out.println(PEMUtils.toPEM(caCertificate));
    }

    public X500Name getSubject() {
        // Create subject CN as pod-name-0-task-name.service-name

        return new X500NameBuilder()
                .addRDN(BCStyle.CN, "CN")
                .addRDN(BCStyle.O, "O")
                .addRDN(BCStyle.L, "beijing")
                .addRDN(BCStyle.ST, "beijing")
                .addRDN(BCStyle.C, "C")
                .build();
    }

    /**
     * Returns additional Subject Alternative Names for service certificates.
     */
    public GeneralNames getSANs() {
        List<GeneralName> generalNames = new ArrayList<>();
        generalNames.add(new GeneralName(GeneralName.dNSName, "192.168.18.160"));
        return new GeneralNames(generalNames.toArray(new GeneralName[0]));
    }
}