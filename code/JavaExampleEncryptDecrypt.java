package AES;

import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONException;
import org.json.JSONObject;


/**
 * Encryption & Decryption for Java 8 or higher
 *
 * For more security, PLEASE use random IV in production
 */
public class JavaExampleEncryptDecrypt {
    static String ivKey;
    final static Base64.Decoder decoder = Base64.getDecoder();
    final static Base64.Encoder encoder = Base64.getEncoder();

    /**
     * The example
     */
    public static void JavaExampleEncryptDecrypt(String[] args) throws Exception {

        // cKey, the Merchant Key, is provided by OneWallet, which had encoded by base64 encoding.
        // The merchant should store it in the persistent storage.
        String cKey = "2KmMsAzSLqe9Q4P+h0hyWw==";
        
        // The original data array
        String[] key1 = { "key1", "value1" };
        String[] key2 = { "key2", "value2" };
        String[] key3 = { "key3", "value3" };
        String[] key4 = { "key4", "value4" };

        // The data converts to JSON string.
        String cVal = putJsonObject(key1, key2, key3, key4).toString();
        
        // Encryption
        String enString = Encrypt(cVal, cKey);
        
        String[] array1 = { "iv", ivKey };
        String[] array2 = { "value", enString };
        String finalText = putJsonObject(array1, array2).toString();
        String response = Base64.getEncoder().encodeToString(finalText.getBytes("UTF-8"));
        System.out.println("Encryption: " + response);
        
        // response = "eyJlcnJvcl9jb2RlIjo0MjIsImRhdGEiOnsibWVzc2FnZSI6IlRoZSBwYXlsb2FkIGlzIGludmFsaWQuIn19";
        // The error message by Base64 Encoding
        try {
            // Decryption
            String DeString = Decrypt(response, cKey);
            System.out.println("Decryption: " + DeString);
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

    public static JSONObject putJsonObject(String[]... values) {
        JSONObject json = new JSONObject();
        try {
            for (String[] val : values) {
                json.put(val[0], val[1]);
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return json;
    }

    /**
     * Encryption
     * For more security, PLEASE use random IV in production
     */
    public static String Encrypt(String sVal, String sKey) throws Exception {
        ivKey = encoder.encodeToString(RandomByte()); // The random IV
        SecretKeySpec skeySpec = new SecretKeySpec(decoder.decode(sKey), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(decoder.decode(ivKey));
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        return encoder.encodeToString(cipher.doFinal(sVal.getBytes()));
    }
    
    // 解密
    public static String Decrypt(String sVal, String sKey) throws Exception {
        JSONObject jsonObject = new JSONObject(new String(decoder.decode(sVal), "UTF-8"));
        if (!jsonObject.isNull("error_code")) {
            throw new Exception((String) ((JSONObject) jsonObject.get("data")).get("message"));
        } else {
            try {
                SecretKeySpec skeySpec = new SecretKeySpec(decoder.decode(sKey), "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                IvParameterSpec iv = new IvParameterSpec(decoder.decode(ivKey));
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
                try {
                    byte[] original = cipher.doFinal(decoder.decode((String) jsonObject.get("value")));
                    String originalString = new String(original);
                    return originalString;
                } catch (Exception e) {
                    System.out.println(e.toString());
                }
            } catch (Exception ex) {
                System.out.println(ex.toString());
            }
            return null;
        }
    }

    public static byte[] RandomByte() {
        byte[] b = new byte[16];
        new Random().nextBytes(b);
        return b;
    }
	
}

