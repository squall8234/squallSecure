import java.io.UnsupportedEncodingException;
import java.util.UUID;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import squall.secure.SecureUtil;



public class MyTest {

	public static void main(String[] args) throws Exception {
		byte[] messageByte = "你好啊".getBytes("UTF-8");
		System.out.println(Base64.encodeBase64String(messageByte));
		/*生成随机秘钥*/
		String key = UUID.randomUUID().toString().replaceAll("-", "").toLowerCase();
		System.out.println(key);
		/*获得随机秘钥byte[]*/
		byte[] aesKey = Hex.decodeHex(key);
		byte[] privteKey = Base64.decodeBase64("MIICXAIBAAKBgQCzQfNPqLEjsfaXEu3qlKYJ9uVkFtPy9Ryl/Flxo9Kw/88LUDR/" + 
				"S9g2mnDjIfaGCxSVJb4KCDMxVOy024HR521PtaKD4SVAKupB0mnDDt6DguZ39ziH" + 
				"mSvY+fHJm8ic+3a/JQWqZADinEz//b5uepYTxE5OIQs0mmlkKVMFkLgI4QIDAQAB" + 
				"AoGAIbDkB5VHkdNpatSKddvxZw8J5ylpNZE/DK1krDijqVOy+MfezgwVu5GEZRQl" + 
				"juT3Pd8FnEIVSRDSml1lRWvPPepSXEsjpo8hJt9nFCTL+hYmu1dFspxxXNueNiHV" + 
				"Y9n1Qn/qnjdsGKY1mSBScY/x5LI3NiVliQRJkmDzGU+eUwkCQQDzS6DbY8VYY6fp" + 
				"8wcMvEtZmZ02l3b2aKQ5U0K6CF/o6+ZNMXaNkWtBXeNtV4+cBNeCG6l4Gmy+w6rC" + 
				"O0nw4mf9AkEAvJ5D35E/aDbQRBlX0wkwKtzc9JZCkKkjK4cemZnLtlrpMiwNI1aI" + 
				"9nuHJKi3BPyG5mjhZbPNy5xw44td1aZ/tQJBAK554x7Smxj7RtUA42Jfuo3EGzmm" + 
				"P7sQag1uR2EQVm+8lQlw2ntF+SwEf+/PJn8V/dMhsVQfZzMbMV9fk3Q7eaUCQHub" + 
				"6HUqVfhw+5m1VhXqTpO4fGEZ2/O7tF3BRi95V8Rg3bRQpCeFfWqy14URwCdXavyy" + 
				"vQwOgo6uLlkgq1TpsYUCQHJnc7n+uCUUN9L7K5mjnDDrl0dZLgZVuXYmW/RzTwBk" + 
				"SdDMSXlHuvnOdqW7BiG30EkeWXg7PlP7f3u6nJQ4dc8=");

		SecureUtil aesUtil = new SecureUtil("AES/CTR/PKCS7Padding");
		//aesUtil.setTransformation("AES/CTR/PKCS7Padding");
		byte[] iv = Hex.decodeHex("12121212121212121212121212121212");
		/*对称加密*/
		byte[] messM = aesUtil.encryptByKey(aesKey, messageByte, iv);
		
		System.out.println(Base64.encodeBase64String(messM));
		SecureUtil rsaUtil = new SecureUtil("RSA/ECB/PKCS1Padding");
		//rsaUtil.setTransformation("RSA/ECB/PKCS1Padding");
		/*加密对称秘钥*/
		byte[] aesMkey = rsaUtil.encryptByPrivateKey(privteKey, aesKey);
		
		
		/*生成签名*/
		byte[] signData = rsaUtil.signByPrivateKey("SHA1withRSA", privteKey, messageByte);
		
		
		
		
		
		
		
		
		
		byte[] publicKey = Base64.decodeBase64("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzQfNPqLEjsfaXEu3qlKYJ9uVk" + 
				"FtPy9Ryl/Flxo9Kw/88LUDR/S9g2mnDjIfaGCxSVJb4KCDMxVOy024HR521PtaKD" + 
				"4SVAKupB0mnDDt6DguZ39ziHmSvY+fHJm8ic+3a/JQWqZADinEz//b5uepYTxE5O" + 
				"IQs0mmlkKVMFkLgI4QIDAQAB");
		
		/*解密对称秘钥*/
		byte[] aesMMkey = rsaUtil.decryptByPublicKey(publicKey, aesMkey);
		System.out.println(Hex.encodeHex(aesMMkey));
		/*对称秘钥解密报文*/
		byte[] message = aesUtil.decryptByKey(aesMMkey, messM, iv);
		System.out.println(Base64.encodeBase64String(message));
		System.out.println(new String(message,"UTF-8"));
		/*验签*/
		System.out.println(rsaUtil.verifyByPublicKey("SHA1withRSA", publicKey, messageByte, signData));
	}

}
