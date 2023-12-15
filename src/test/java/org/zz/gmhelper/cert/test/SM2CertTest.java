package org.zz.gmhelper.cert.test;

import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;

import java.io.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class SM2CertTest {

    public static void main(String[] args) throws IOException {
        String text = "我是一段测试aaaa";

        KeyPair pair = SecureUtil.generateKeyPair("SM2");
        byte[] privateKeyArray = pair.getPrivate().getEncoded();
        byte[] publicKeyArray = pair.getPublic().getEncoded();
        writeBytesToFile(privateKeyArray, "d:/privatekey.pem");
        writeBytesToFile(publicKeyArray, "d:/publickey.pem");

        PrivateKey privateKey = SecureUtil.generatePrivateKey("SM2", getBytesFromFile(new File("d:/privatekey.pem")));
        PublicKey publicKey = SecureUtil.generatePublicKey("SM2", getBytesFromFile(new File("d:/publickey.pem")));
        SM2 sm2 = new SM2();
        sm2.setPrivateKey(privateKey);
        sm2.setPublicKey(publicKey);

        // 公钥加密，私钥解密
        String encryptStr = sm2.encryptBcd(text, KeyType.PublicKey);
        System.out.println(encryptStr);
        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));
        System.out.println(decryptStr);
    }



    public static void writeBytesToFile(byte[] bs, String path) throws IOException {

        OutputStream out = new FileOutputStream(path);
        InputStream is = new ByteArrayInputStream(bs);
        byte[] buff = new byte[1024];
        int len = 0;
        while ((len = is.read(buff)) != -1) {
            out.write(buff, 0, len);
        }
        is.close();
        out.close();
    }

    // 返回一个byte数组
    public static byte[] getBytesFromFile(File file) throws IOException {
        InputStream is = new FileInputStream(file);// 获取文件大小
        long lengths = file.length();
        System.out.println("lengths = " + lengths);
        if (lengths > Integer.MAX_VALUE) {
            // 文件太大，无法读取
            throw new IOException("File is to large " + file.getName());
        }
        // 创建一个数据来保存文件数据
        byte[] bytes = new byte[(int) lengths];// 读取数据到byte数组中
        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
            offset += numRead;
        }
        // 确保所有数据均被读取
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file " + file.getName());
        }
        // Close the input stream and return bytes
        is.close();
        return bytes;
    }
}
