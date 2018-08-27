package com.bamboonetworks.modules.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.Security;

/**
 * @author tomy.tang
 */
public class PasswordHandler {

	@Value("${password.encrypt.key}")
	private String key;

	//向量参数
	private static final String iv   = "bambootechnology";

	private static final IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());

	public String getEncodedPassword(final String password){
		try{
			Security.addProvider(new BouncyCastleProvider());
			byte[] keyByte = DatatypeConverter.parseBase64Binary(key);
			SecretKey secretKey = new SecretKeySpec(keyByte, "AES");

			//改变密码规则在第一个event结束后改变下面2行
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding","BC");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey,generateIV());
			//Cipher cipher = Cipher.getInstance("AES");
			//cipher.init(Cipher.ENCRYPT_MODE, secretKey);


			//cipher.update(password.getBytes());
			byte[] result = cipher.doFinal(password.getBytes());
			return DatatypeConverter.printBase64Binary(result);
		}catch(Exception e){
			e.printStackTrace();
			return "";
		}		
	}
	
    private IvParameterSpec generateIV() throws Exception {
        byte[] ivBytes = iv.getBytes();
        return new IvParameterSpec(ivBytes);
    }

}
