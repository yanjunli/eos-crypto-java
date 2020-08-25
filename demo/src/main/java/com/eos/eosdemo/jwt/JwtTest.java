package com.eos.eosdemo.jwt;

import com.eos.crypto.ec.EosPrivateKey;
import com.eos.crypto.ec.EosPublicKey;
import com.eos.eosdemo.jwt.utils.JwtTool;
import io.jsonwebtoken.SignatureAlgorithm;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class JwtTest {

    static{
        try{
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public void tokenTest() throws Exception {

        String senderPrivateKey =  "5KTZYCDdcfNrmEpcf97SJBCtToZjYHjHm8tqTWvzUbsUJgkxcfk";
        EosPrivateKey senderECPrivateKey = new EosPrivateKey(senderPrivateKey);

        System.out.println(senderECPrivateKey.toString());

        // 转换成 EC privatekey
        ECPrivateKey ecPrivateKey = senderECPrivateKey.getECPrivateKey();

        System.out.println(ecPrivateKey.toString());

        EosPublicKey senderECPublicKey = senderECPrivateKey.getPublicKey();

        System.out.println(senderECPublicKey.toString());

        // 转换成 EC publickey
        ECPublicKey ecPublicKey = senderECPublicKey.getECPublicKey();

        System.out.println(ecPublicKey);

        /*
         *  把 eos 账号，或者其他信息放进payload 中。
         */
        String eosaccount = "xxxxxxxx";

        System.out.println("eos 账号 " + eosaccount);

        /*
              私钥签名，生成token
         */
        String token = JwtTool.generateToken(ecPrivateKey,eosaccount,eosaccount.hashCode()+"");

        SignatureAlgorithm alg = SignatureAlgorithm.forSigningKey(ecPrivateKey);

        System.out.println("使用的算法"+alg.getDescription());

        System.out.println("生成的token：  "+token);

        /*
            传递公钥，验签 token
         */
        boolean result = JwtTool.verifyToken(token,ecPublicKey);

        System.out.println("验证结果:  " + result);

        System.out.println("eos 账号 "+JwtTool.getAccount(token,ecPublicKey));
    }
}
