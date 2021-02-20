package vip.aquan.rsademo.util;


import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSA加解密工具
 * 说明：
 * 1.加解密、验签不限制公私钥先后顺序，只要符合公钥加密，私钥解密 或 私钥加密，公钥解密即可
 * 2.加解密是为了传输信息防止被抓包泄露；验签是为了防止被篡改，确保是发送者本人
 * 3.分段加解密是因为RSA加密对明文的长度有所限制，规定需加密的明文最大长度=密钥长度-11=117字节
 * 为啥两者相差11字节呢？是因为RSA加密使用到了填充模式（padding），
 * 即内容不足117字节时会自动填满，用到填充模式自然会占用一定的字节，而且这部分字节也是参与加密的
 * 4.B公钥加密-->A私钥签名-->A公钥验签-->B私钥解密 ，通常是以此方式进行交互，若不对外传输，仅内部使用，AB也可以公用密钥？
 */
public class RSAUtil {

    public static final String SIGN_ALGORITHMS = "SHA256WithRSA";
    public static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

    /** */
    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /** */
    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

    /**
     * 生成密钥对
     * @return
     * @throws Exception
     */
    public static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        return generator.generateKeyPair();
    }


    /**
     * 签名
     *
     * @param content
     * @param privateKey
     * @return
     */
    public static String sign(String content, String privateKey) {
        try {
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
            KeyFactory keyf = KeyFactory.getInstance("RSA");
            PrivateKey priKey = keyf.generatePrivate(priPKCS8);
            Signature signature = Signature.getInstance(SIGN_ALGORITHMS);
            signature.initSign(priKey);
            signature.update(content.getBytes(DEFAULT_CHARSET));
            byte[] signed = signature.sign();
            return Base64.getEncoder().encodeToString(signed);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 验签
     *
     * @param content
     * @param sign
     * @param publicKey
     * @return
     */
    public static boolean verify(String content, String sign, String publicKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] encodedKey = Base64.getDecoder().decode(publicKey);
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));

            Signature signature = Signature.getInstance(SIGN_ALGORITHMS);

            signature.initVerify(pubKey);
            signature.update(content.getBytes(DEFAULT_CHARSET));

            return signature.verify(Base64.getDecoder().decode(sign));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }


    /**
     * 将base64编码后的公钥字符串转成PublicKey实例
     * @param key
     * @return
     * @throws Exception
     */
    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 将base64编码后的私钥字符串转成PrivateKey实例
     * @param key
     * @return
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }


    /**
     * 公钥分段加密
     *
     * @param content
     * @param publicKeyStr
     * @return
     * @throws Exception
     */
    public static String publicEncrpyt(String content, String publicKeyStr) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(1, getPublicKey(publicKeyStr));
        byte[] bytes = content.getBytes(DEFAULT_CHARSET);

        int inputLen = bytes.length;
        int offSet = 0;
        byte[] cache;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(bytes, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(bytes, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return Base64.getEncoder().encodeToString(encryptedData);
    }


    /**
     * 私钥分段加密
     *
     * @param content
     * @param privateKeyStr
     * @return
     * @throws Exception
     */
    public static String privateEncrpyt(String content, String privateKeyStr) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(1, getPrivateKey(privateKeyStr));
        byte[] bytes = content.getBytes(DEFAULT_CHARSET);

        int inputLen = bytes.length;
        int offSet = 0;
        byte[] cache;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(bytes, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(bytes, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return Base64.getEncoder().encodeToString(encryptedData);
    }


    /**
     * 私钥分段解密
     *
     * @param content
     * @param privateKeyStr
     * @return
     * @throws Exception
     */
    public static String privateDecrypt(String content, String privateKeyStr) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(2, getPrivateKey(privateKeyStr));
        byte[] bytes = Base64.getDecoder().decode(content);
        int inputLen = bytes.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(bytes, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(bytes, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return new String(decryptedData);
    }


    /**
     * 公钥分段解密
     *
     * @param content
     * @param publicKeyStr
     * @return
     * @throws Exception
     */
    public static String publicDecrypt(String content, String publicKeyStr) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(2, getPublicKey(publicKeyStr));
        byte[] bytes = Base64.getDecoder().decode(content);
        int inputLen = bytes.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(bytes, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(bytes, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return new String(decryptedData);
    }

    public static void main(String[] args) throws Exception {

        //生成公私钥
        /*KeyPair keyPair = getKeyPair();
        String privateKey = new String(Base64.getEncoder().encode(keyPair.getPrivate().getEncoded()));
        String publicKey = new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded()));
        System.out.println("私钥:" + privateKey);
        System.out.println("公钥:" + publicKey);*/

        String content = "这是要加密的内容";
        //公钥216
        String publicKey ="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCocv9nyZlKbz9bepQGjaOkpkHLZVvN+G9ExM1hw2yjYfUB5eGhjDtATrkrB7QkOhMcXuDhvRq9OUSvRBCPkD07q/teUVIG3oIMdxvI3vCuGKkP7q+y/Suz8OF4l+I/GtO0y1R31SZI9p96UiCbp0kZkOko9T3iZ95eu+VBJalV0QIDAQAB";
        //私钥844
        String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKhy/2fJmUpvP1t6lAaNo6SmQctlW834b0TEzWHDbKNh9QHl4aGMO0BOuSsHtCQ6Exxe4OG9Gr05RK9EEI+QPTur+15RUgbeggx3G8je8K4YqQ/ur7L9K7Pw4XiX4j8a07TLVHfVJkj2n3pSIJunSRmQ6Sj1PeJn3l675UElqVXRAgMBAAECgYAEASfdOcexI0/oRtO6DCf1xBYQVcqG7P8ILX2Mc27ju3Jtpx9kDcdi0fxI75fyvIazx/WkqDA4i2H8oKucHhu2g3qjSoizjmKm4e8eJh5SeIy1JKe3yjym+Q4cZC/+la0LDg+oOqYpLTYF+PVvCGD8xjtqUbNvoo7YdAQ7k5AheQJBAO4/cp60/Wzqtg6b+qBAG7lAL6inXof2RpgRYFnlC1TAogYogp9vc+RFxCnD8u8KcsWSNjmd236Yy2P0gA3/2+sCQQC1ACYAK6Vc2n9j5f6tsCV0P4UFJtGsBENUsPdUmdSGtfOyptECtohGu8bBmXTT2JZ9wKzhdRYHbSxXf8YOLhIzAkEAxclol3b72Nr1ryUwqK7wFRfDOQlRgiAjNQVf7uEmSgLtv50L695z4LNGicHBwU70Py8F00lIuk2QtHd7g6PAZwJAfKsBgZSObYpBvDkqVc/BvHQT1xyJxoWZKrhJYwghjje9BwxHYir/aljj6W0dPt0rqqoPaasP5UWZCRuE+zdYaQJAURpY/WRfF2hohb6Wv0QOXrQYXAPc/5TsMbgseG5N7UbVHl4tK3z3LixRUGtTootLCR02D+bg1x+IEtjGmjSDfQ==";

        //公钥加密-->私钥签名-->公钥验签-->私钥解密
        //公钥加密
        String s = publicEncrpyt(content, publicKey);
        System.out.println("公钥加密后："+s);

        //签名     Authorization
        String sign = sign(s, privateKey);
        System.out.println("私钥签名后："+sign);

        //验签
        boolean verify = verify(s, sign, publicKey);
        System.out.println("用公钥验签后："+verify);

        //私钥解密
        String s1 = privateDecrypt(s, privateKey);
        System.out.println("解密后："+s1 );

    }


}
