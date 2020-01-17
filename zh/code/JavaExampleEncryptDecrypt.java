package ACE;

import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONException;
import org.json.JSONObject;

public class Main {
    static String ivKey = "1osdDsvHRXvVcVLFyzgI6w==";
    final static Base64.Decoder decoder = Base64.getDecoder();
    final static Base64.Encoder encoder = Base64.getEncoder();

    public static void main(String[] args) throws Exception {
        /*
         * 加解密 for java 8 higher
         * 
         * 生产环境请使用随机 iv 值以提高安全性 API测试串接时可使用固定 iv 值: 1osdDsvHRXvVcVLFyzgI6w==
         * 正确加密後会得到加密字串:
         * eyJpdiI6IjFvc2REc3ZIUlh2VmNWTEZ5emdJNnc9PSIsInZhbHVlIjoib2g2bEUwYThtMU4wWXB5b21mcDhUUmNzZ3QycGFNS0xuUzgzZzg1SXpsYUJGUVY1UEZ0VE85UWI2NmtRT0FRUXVoakpLMlUrOHBUL3duSXFibkJ1cUU2NHJhOTRPakdwOUluU2drUHVzSUk9In0=
         */

        // 商户安全码 (已 base64_encode 的 byte 资料)
        String cKey = "2KmMsAzSLqe9Q4P+h0hyWw==";
        // 需要加密的字串
        String[] key1 = { "key1", "value1" };
        String[] key2 = { "key2", "value2" };
        String[] key3 = { "key3", "value3" };
        String[] key4 = { "key4", "value4" };

        String cVal = putJsonObject(key1, key2, key3, key4).toString();
        // 加密
        String enString = Encrypt(cVal, cKey);
        // 需要加密的字串
        String[] array1 = { "iv", "1osdDsvHRXvVcVLFyzgI6w==" };
        String[] array2 = { "value", enString };
        String finalText = putJsonObject(array1, array2).toString();
        String response = Base64.getEncoder().encodeToString(finalText.getBytes("UTF-8"));
        System.out.println("正确加密後会得到加密字串：" + response);

//      response = "eyJlcnJvcl9jb2RlIjo0MjIsImRhdGEiOnsibWVzc2FnZSI6IlRoZSBwYXlsb2FkIGlzIGludmFsaWQuIn19"; //加密錯誤訊息的解析
        
        try {
            // 解密
            String DeString = Decrypt(response, cKey);
            System.out.println("解密后的字串是：" + DeString);
        } catch (Exception e) {
            System.out.println(e.toString());
//          e.printStackTrace();
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

    // 加密
    public static String Encrypt(String sVal, String sKey) throws Exception {
        // ivKey = encoder.encodeToString(RandomByte());// 随机 iv 值 (生产环境请使用随机 iv 值)
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
