package squall.secure;

import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 加密解密工具类，内置了支持JCE和BC
 * 
 * @author squall
 *
 */
public class SecureUtil {

	/**
	 * 转换格式 算法/模式/填充方式,如果只填入算法则根据当前Provider此算法的默认模式和填充实现 如
	 * "RSA/ECB/Pkcs1padding"，只填算法如"RSA"
	 */
	private String transformation;

	/*
	 * 懒得再次设置，直接从transformation从获取
	 */
	private String algorithm;

	/**
	 * 设置使用的加密算法的Provider，注意此处目前如果是默认使用BouncyCastle，
	 * 传递BouncyCastleProvider.PROVIDER_NAME 不设置默认JCE现实
	 */
	private String cipherProvider;

	/**
	 * 设置使用的加密使用的秘钥的Provider， 不设置默认JCE现实
	 */
	private String keyProvider;

	static {
		/* 注入BouncyCastleProvider */
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * 使用私钥对数据进行加密
	 * 
	 * @param privateKey 私钥的对象
	 * @param data       待加密数据
	 * @return 加密后的数据
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public byte[] encryptByPrivateKey(PrivateKey privateKey, byte[] data) throws Exception {
		Cipher cipher = null;
		if (cipherProvider != null && !"".equals(cipherProvider)) {
			cipher = Cipher.getInstance(transformation, cipherProvider);
		} else {
			cipher = Cipher.getInstance(transformation);
		}
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		return cipher.doFinal(data);
	}

	/**
	 * 使用私钥对数据进行解密
	 * 
	 * @param privateKey 私钥的对象
	 * @param data       待解密数据
	 * @return 解密后的数据
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public byte[] decryptByPrivateKey(PrivateKey privateKey, byte[] data) throws Exception {
		Cipher cipher = null;
		if (cipherProvider != null && !"".equals(cipherProvider)) {
			cipher = Cipher.getInstance(transformation, cipherProvider);
		} else {
			cipher = Cipher.getInstance(transformation);
		}
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(data);
	}

	/**
	 * 使用公钥对数据进行加密
	 * 
	 * @param publicKey 公钥的对象
	 * @param data      待加密数据
	 * @return 加密后的数据
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public byte[] encryptByPublicKey(PublicKey publicKey, byte[] data) throws Exception {
		Cipher cipher = null;
		if (cipherProvider != null && !"".equals(cipherProvider)) {
			cipher = Cipher.getInstance(transformation, cipherProvider);
		} else {
			cipher = Cipher.getInstance(transformation);
		}
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}

	/**
	 * 使用公钥对数据进行解密
	 * 
	 * @param publicKey 公钥的对象
	 * @param data      待解密数据
	 * @return 解密后的数据
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public byte[] decryptByPublicKey(PublicKey publicKey, byte[] data) throws Exception {
		Cipher cipher = null;
		if (cipherProvider != null && !"".equals(cipherProvider)) {
			cipher = Cipher.getInstance(transformation, cipherProvider);
		} else {
			cipher = Cipher.getInstance(transformation);
		}
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}

	/**
	 * 使用秘钥的字节数组对数据进行加密，注意此处的数据应该能用于构建PKCS8EncodedKeySpec对象
	 * 
	 * @param keyData 私钥的数据
	 * @param data    待加密数据
	 * @return 加密后的数据
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public byte[] encryptByPrivateKey(byte[] keyData, byte[] data) throws Exception {
		KeyFactory keyFactory = null;
		if (keyProvider != null && !"".equals(keyProvider)) {
			keyFactory = KeyFactory.getInstance(algorithm, keyProvider);
		} else {
			keyFactory = KeyFactory.getInstance(algorithm);
		}
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyData);
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
		return encryptByPrivateKey(privateKey, data);
	}

	/**
	 * 使用秘钥的字节数组对数据进行解密，注意此处的数据应该能用于构建PKCS8EncodedKeySpec对象
	 * 
	 * @param keyData 私钥的数据
	 * @param data    待解密数据
	 * @return 加密后的数据
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public byte[] decryptByPrivateKey(byte[] keyData, byte[] data) throws Exception {
		KeyFactory keyFactory = null;
		if (keyProvider != null && !"".equals(keyProvider)) {
			keyFactory = KeyFactory.getInstance(algorithm, keyProvider);
		} else {
			keyFactory = KeyFactory.getInstance(algorithm);
		}
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyData);
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
		return decryptByPrivateKey(privateKey, data);
	}

	/**
	 * 使用公钥的字节数组对数据进行加密，注意此处的数据应该能用于构建X509EncodedKeySpec对象
	 * 
	 * @param keyData 公钥的数据
	 * @param data    待加密的数据
	 * @return 加密后的数据
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public byte[] encryptByPublicKey(byte[] keyData, byte[] data) throws Exception {
		KeyFactory keyFactory = null;
		if (keyProvider != null && !"".equals(keyProvider)) {
			keyFactory = KeyFactory.getInstance(algorithm, keyProvider);
		} else {
			keyFactory = KeyFactory.getInstance(algorithm);
		}
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyData);
		PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);
		return encryptByPublicKey(publicKey, data);
	}

	/**
	 * 使用公钥的字节数组对数据进行解密，注意此处的数据应该能用于构建X509EncodedKeySpec对象
	 * 
	 * @param keyData 公钥的数据
	 * @param data    待解密的数据
	 * @return 解密后的数据
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public byte[] decryptByPublicKey(byte[] keyData, byte[] data) throws Exception {
		KeyFactory keyFactory = null;
		if (keyProvider != null && !"".equals(keyProvider)) {
			keyFactory = KeyFactory.getInstance(algorithm, keyProvider);
		} else {
			keyFactory = KeyFactory.getInstance(algorithm);
		}
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyData);
		PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);
		return decryptByPublicKey(publicKey, data);
	}

	/**
	 * 使用秘钥的字节数组的BASE64编码数据对数据进行加密，注意此处的keyDataStr decodeBase64后的
	 * 数据应该能用于构建PKCS8EncodedKeySpec对象
	 * 
	 * @param keyDataStr 私钥的数据的BASE64编码
	 * @param data       待加密数据BASE64编码
	 * @return 加密后的数据BASE64编码
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public String encryptByPrivateKey(String keyDataStr, String dataStr) throws Exception {
		byte[] keyData = Base64.decodeBase64(keyDataStr);
		byte[] data = Base64.decodeBase64(dataStr);
		return Base64.encodeBase64String(encryptByPrivateKey(keyData, data));
	}

	/**
	 * 使用秘钥的字节数组的BASE64编码数据对数据进行解密，注意此处的keyDataStr decodeBase64后的
	 * 数据应该能用于构建PKCS8EncodedKeySpec对象
	 * 
	 * @param keyDataStr 私钥的数据的BASE64编码
	 * @param data       待解密数据BASE64编码
	 * @return 解密后的数据BASE64编码
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public String decryptByPrivateKey(String keyDataStr, String dataStr) throws Exception {
		byte[] keyData = Base64.decodeBase64(keyDataStr);
		byte[] data = Base64.decodeBase64(dataStr);
		return Base64.encodeBase64String(decryptByPrivateKey(keyData, data));
	}

	/**
	 * 使用公钥的字节数组的BASE64编码数据对数据进行加密，注意此处的keyDataStr decodeBase64后的
	 * 数据应该能用于构建X509EncodedKeySpec对象
	 * 
	 * @param keyDataStr 公钥的数据的BASE64编码
	 * @param data       待加密数据BASE64编码
	 * @return 加密后的数据BASE64编码
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public String encryptByPublicKey(String keyDataStr, String dataStr) throws Exception {
		byte[] keyData = Base64.decodeBase64(keyDataStr);
		byte[] data = Base64.decodeBase64(dataStr);
		return Base64.encodeBase64String(encryptByPublicKey(keyData, data));
	}

	/**
	 * 使用公钥的字节数组的BASE64编码数据对数据进行解密，注意此处的keyDataStr decodeBase64后的
	 * 数据应该能用于构建X509EncodedKeySpec对象
	 * 
	 * @param keyDataStr 公钥的数据的BASE64编码
	 * @param data       待解密数据BASE64编码
	 * @return 加密后的数据BASE64编码
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public String decryptByPublicKey(String keyDataStr, String dataStr) throws Exception {
		byte[] keyData = Base64.decodeBase64(keyDataStr);
		byte[] data = Base64.decodeBase64(dataStr);
		return Base64.encodeBase64String(decryptByPublicKey(keyData, data));
	}

	/**
	 * 对称加密算法加密
	 * 
	 * @param key    对称秘钥对象
	 * @param data   待加密数据
	 * @param ivData iv的数据，ECB模式则不传
	 * @return 加密后的数据
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public byte[] encryptByKey(Key key, byte[] data, byte[]... ivData) throws Exception {
		Cipher cipher = null;
		if (cipherProvider != null && !"".equals(cipherProvider)) {
			cipher = Cipher.getInstance(transformation, cipherProvider);
		} else {
			cipher = Cipher.getInstance(transformation);
		}
		if (ivData != null) {
			IvParameterSpec iv = new IvParameterSpec(ivData[0]);
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		} else {
			cipher.init(Cipher.ENCRYPT_MODE, key);
		}
		return cipher.doFinal();
	}

	/**
	 * 对称加密算法解密
	 * 
	 * @param key    对称秘钥对象
	 * @param data   待解密数据
	 * @param ivData iv的数据，ECB模式则不传
	 * @return 解密后的数据
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public byte[] decryptByKey(Key key, byte[] data, byte[]... ivData) throws Exception {
		Cipher cipher = null;
		if (cipherProvider != null && !"".equals(cipherProvider)) {
			cipher = Cipher.getInstance(transformation, cipherProvider);
		} else {
			cipher = Cipher.getInstance(transformation);
		}
		if (ivData != null) {
			IvParameterSpec iv = new IvParameterSpec(ivData[0]);
			cipher.init(Cipher.DECRYPT_MODE, key, iv);
		} else {
			cipher.init(Cipher.DECRYPT_MODE, key);
		}
		return cipher.doFinal();
	}

	/**
	 * 对称加密算法加密
	 * 
	 * @param keyData 对称秘钥字节数组，用于构造SecretKey
	 * @param data    待加密数据
	 * @param ivData  iv的数据，ECB模式则不传
	 * @return 加密后的数据
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public byte[] encryptByKey(byte[] keyData, byte[] data, byte[]... ivData) throws Exception {
		SecretKey key = new SecretKeySpec(keyData, algorithm);
		return encryptByKey(key, data, ivData);
	}

	/**
	 * 对称加密算法解密
	 * 
	 * @param keyData 对称秘钥字节数组，用于构造SecretKey
	 * @param data    待解密数据
	 * @param ivData  iv的数据，ECB模式则不传
	 * @return 解密后的数据
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public byte[] decryptByKey(byte[] keyData, byte[] data, byte[]... ivData) throws Exception {
		SecretKey key = new SecretKeySpec(keyData, algorithm);
		return decryptByKey(key, data, ivData);
	}

	/**
	 * 对称加密算法加密
	 * 
	 * @param keyDataStr 对称秘钥字节数组BASE64编码，用于构造SecretKey
	 * @param data       待加密数据BASE64编码
	 * @param ivDataStr  iv数据的BASE64编码
	 * @return 加密后的数据BASE64编码
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public String encryptByKey(String keyDataStr, String dataStr, String... ivDataStr) throws Exception {

		byte[] keyData = Base64.decodeBase64(keyDataStr);
		byte[] data = Base64.decodeBase64(dataStr);
		byte[] ivData = null;
		if (ivDataStr != null) {
			ivData = Base64.decodeBase64(ivDataStr[0]);
		}
		return Base64.encodeBase64String(encryptByKey(keyData, data, ivData));
	}

	/**
	 * 对称解密算法解密
	 * 
	 * @param keyDataStr 对称秘钥字节数组BASE编码，用于构造SecretKey
	 * @param dataStr    待解密数据BASE编码
	 * @param ivDataStr  iv数据的BASE64编码
	 * @return 解密后的数据BASE64编码
	 * @throws Exception 太多了，如果以后需要有特殊处理的实现，会在内部进行处理以容错
	 */
	public String decryptByKey(String keyDataStr, String dataStr, String... ivDataStr) throws Exception {
		byte[] keyData = Base64.decodeBase64(keyDataStr);
		byte[] data = Base64.decodeBase64(dataStr);
		byte[] ivData = null;
		if (ivDataStr != null) {
			ivData = Base64.decodeBase64(ivDataStr[0]);
		}
		return Base64.encodeBase64String(decryptByKey(keyData, data, ivData));
	}

	/**
	 * 设置转换格式 算法/模式/填充方式,如果只填入算法则根据当前Provider此算法的默认模式和填充实现
	 * 
	 * @param transformation 如"RSA/ECB/Pkcs1padding"，只填算法如"RSA"
	 */
	public void setTransformation(String transformation) {
		int idx = transformation.indexOf('/');
		if (idx == -1) {
			this.algorithm = transformation;
		} else {
			this.algorithm = transformation.substring(0, idx);
		}
		this.transformation = transformation;
	}

	/**
	 * 设置加解密使用的Provider，如果不设置默认JCE
	 * 
	 * @param cipherProvider
	 */
	public void setCipherProvider(String cipherProvider) {
		this.cipherProvider = cipherProvider;
	}

	/**
	 * 设置秘钥使用的Provider，如果不设置默认JCE
	 * 
	 * @param keyProvider
	 */
	public void setKeyProvider(String keyProvider) {
		this.keyProvider = keyProvider;
	}

}
