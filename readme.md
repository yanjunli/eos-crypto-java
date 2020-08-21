# **eos-crypto-java 使用指南**

源码：https://github.com/yanjunli/eos-crypto-java

eos-crypto-java 目前可以支持 基于 ECC+AES 的加解密方式。 

在本压缩包中，包含基于jdk1.5 打好的jar 包。


## 要求

jdk 1.5+

## 加解密示例

```java
/**
*
* sender  发起方密钥对
*
* EOS8g1u3ktAGHs4QsVp9aeaWNebFLtprQHwpaSjegx6iEuoTNhjXU
* 5KTZYCDdcfNrmEpcf97SJBCtToZjYHjHm8tqTWvzUbsUJgkxcfk
*
* receiver 接收方一密钥对
*
* EOS7ez2gagfoXw9XdW3kRx3EsCoWvupGR6u6ZJhFPEe9Q12V8JgUL
* 5JUrqxYcssR9LLVtWDeQcc9HCX4FEqBG7d9GW6t7mvmB1rUuZr9
*
* receiver 接收方二 密钥对
* EOS5WMHqw6jDDBPBm7JXTHemAwtSo2tp93pRysJMRhiT1zUYb24vL
* 5HrcVeuHHNwHsivrMoJ9XvU6EM7Q2wQ2ECiy8GeoiuamhNiSuZq
*/

// 1.  调用钱包获取 发送方私钥
  String senderPrivateKey =  "5KTZYCDdcfNrmEpcf97SJBCtToZjYHjHm8tqTWvzUbsUJgkxcfk";
  EosPrivateKey senderECPrivateKey = new EosPrivateKey(senderPrivateKey);
//        EosPublicKey senderECPublicKey = new EosPublicKey(senderPublicKey);
        // 2.  根据私钥 生成公钥。 或者直接根据公钥 调用钱包获取私钥。 都可以。
  EosPublicKey senderECPublicKey = senderECPrivateKey.getPublicKey();

  String senderPublicKey = senderECPublicKey.toString();
  /**
   * 调用钱包获取 接收方私钥   获取公私钥方式 根据需求确定。
   *  1. 可以根据公钥，从钱包里获取私钥
   *  2. 也可以直接从钱包里取出私钥，反向生成公钥
   *  
   *  实际业务场景，发起方只会有接收方公钥，并没有接收方私钥. 
   *  此时 可以通过 new EosPublicKey(receiverPublicKey) 方式 生成EosPublicKey 对象。
   */
  String receiverPrivateKey = "5JUrqxYcssR9LLVtWDeQcc9HCX4FEqBG7d9GW6t7mvmB1rUuZr9";
  EosPrivateKey receiverECPrivateKey = new EosPrivateKey(receiverPrivateKey);
  EosPublicKey receiverECPublicKey = receiverECPrivateKey.getPublicKey();
  String receiverPublicKey = receiverECPublicKey.toString();
  //        String receiverPublicKey =  "EOS7ez2gagfoXw9XdW3kRx3EsCoWvupGR6u6ZJhFPEe9Q12V8JgUL";


  /**
   * 使用 发送者方私钥 和接收方公钥，生成 aes key, 对数据进行加密
   * nonce  为初始化向量，可以使用固定值，
   *                      也可以使用随机值，并使用私有协议。根据业务需求选择。
   */
  byte[] nonce = new byte[16];
  MTRandom random=new MTRandom();
  random.nextBytes(nonce);

  // 待加密 数据
  byte[] params = "{\"test1\": 1,\"test2\":\"24qqwazzxdtttdxkaskjewuizckczxnlsdosasda4!!!@#$$%^&&*((){}(^#\"}".getBytes("utf8");

  System.out.println("原始加密数据： " + new String(params,"utf8"));

  byte[] encrypted = new byte[0];
  try {
      encrypted = CryptUtil.encrypt(senderECPrivateKey,receiverECPublicKey,nonce,params);
  } catch (InvalidCipherTextException e) {
      e.printStackTrace();
      System.out.println("  do something!!!!");
  }

  System.out.println("加密后数据： " + new String(encrypted,"utf8"));
  try {
      byte[] plainText = CryptUtil.decrypt(receiverECPrivateKey,senderECPublicKey,nonce,encrypted);
      // 解密后数据
      System.out.println("解密后数据 :  "+new String(plainText, "utf8"));
  } catch (InvalidCipherTextException e) {
      e.printStackTrace();
      System.out.println("  do something!!!!");
  }
```


## 基于ECC+AES 双向验证的 IPFS 加密传输示例


```java

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
        byte[] params = "{\"age\": 1,\"汉字\":\"汉字测试。为初始化向量，可以使用固定值，\"，\"12345\":\"24qqwazzxdtttdxkaskjewuizckczxnlsdosasda4!!!@#$$%^&&*(()(^#\"}".getBytes("utf8");

        System.out.println("原始加密数据： " + new String(params,StandardCharsets.UTF_8));

        byte[] encrypted = new byte[0];
        try {
            encrypted = CryptUtil.encrypt(senderECPrivateKey,receiverECPublicKey,nonce,params);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            System.out.println("  do something!!!!");
        }

        System.out.println("加密后数据： " + Base58.encode(encrypted));

        JsonObject object = new JsonObject();
        object.addProperty("Data", Base58.encode(encrypted));

        List<byte[]> objectData = new ArrayList<>(1);

        objectData.add(object.toString().getBytes(StandardCharsets.UTF_8));

        List<MerkleNode> merkleNodes =  ipfs.object.put(objectData);

        MerkleNode node = merkleNodes.get(0);

        /**
         * 可以将该值，上传到区块链网络中。
         */
        String nodeHash = node.hash.toBase58();

        System.out.println( " 上传 ipfs 后，获取到的 hash值 "+ nodeHash);

        System.out.println(" 根据 上传获取到的 ipfs hash，从 ipfs 下载 数据。");

        Multihash multihash = Multihash.fromBase58(nodeHash);

        MerkleNode merkleNode = ipfs.object.get(multihash);

        byte[] ipfsData = merkleNode.data.get();

        System.out.println("从 ipfs 获得到的数据 "+new String(ipfsData));

        byte[] decode = Base58.decode(new String(ipfsData));

        try {
            byte[] plainText = CryptUtil.decrypt(receiverECPrivateKey,senderECPublicKey,nonce,decode);
            // 解密后数据
            System.out.println("解密后数据 :  "+new String(plainText, "utf8"));
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            System.out.println("  do something!!!!");
        }

```
