package ACE;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.json.JSONObject;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class JavaExampleEncryptDecrypt {
	private static SimpleDateFormat dateFormatWithZone = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss",
			Locale.getDefault());
	public static Gson gson = new GsonBuilder().disableHtmlEscaping().create();
	
	// The URL of Onewallet. The merchant would get a specific one by OneWallet consultant.
	static String requestUrl = "https://api-tg.100scrop.tech/1-49b/SH/sendPay";
	
	// The random 16 bytes with Base64 Encoding. For instance: 1osdDsvHRXvVcVLFyzgI6w==
 	static String ivKey = ""; 
	
	static String cKey = "";
	
	static MyTrustManager mMyTrustManager;
	
	final static Base64.Decoder decoder = Base64.getDecoder();
	final static Base64.Encoder encoder = Base64.getEncoder();

	/*
	 ** Encrytion & Decrytion sample by JAVA 8 or higher
	 */
	public static void main(String[] args) throws Exception {
		

		// The random IV key
		ivKey = encoder.encodeToString(RandomByte());
		
		// The merchant's MD5 key
		cKey = "X4eTAkFmmnpg0N43uLgaIA==";
		
		// The specific data
		Map<String, String> map = new LinkedHashMap<>();
		map.put("sh_order_no", "1061692220003");
		map.put("order_amount", "0.1");
		map.put("order_type", "100");
		map.put("bank_code", "KTB");
		map.put("created_at", getCurrentDate());
		// The notify URL is just a example as below, would be provided by merchant.
		map.put("notify_url", "https://www.notify.com/api/callback/DepositCallbackHandler.php");
		map.put("note", "note");

		String cVal = putJsonObject(map);
		// Encrypt data
		System.out.println("Data before encrytion: " + cVal);
		String enString = Encrypt(cVal, cKey);
		map.clear();
		map.put("iv", ivKey);
		map.put("value", enString);
		String finalText = putJsonObject(map);
		
		String dataBeforeSending = Base64.getEncoder().encodeToString(finalText.getBytes("UTF-8"));
		System.out.println("The body of the request: " + dataBeforeSending);
		
		try {
			// Decrypt data
			String deString = Decrypt(dataBeforeSending, cKey);
			// Verify the data should be identical after decrytion
			System.out.println("Data after decrytion: " + deString);
		} catch (Exception e) {
			System.out.println(e.toString());
//			e.printStackTrace();
		}
		post(dataBeforeSending);
	}

	public static String getCurrentDate() {
		return dateFormatWithZone.format(new Date());
	}

	public static String putJsonObject(Map<String, String> map) {
		return gson.toJson(map);
	}

	public static void post(String bodyString) throws IOException {
		OkHttpClient.Builder builder = new OkHttpClient.Builder();
		builder.sslSocketFactory(createSSLSocketFactory(), mMyTrustManager);
		builder.hostnameVerifier(new TrustAllHostnameVerifier());
		OkHttpClient client = builder.build();
		RequestBody body = RequestBody.create(MediaType.parse("application/json; charset=utf-8"), bodyString);
		Request request = new Request.Builder().url(requestUrl).post(body).build();
		client.newCall(request).enqueue(new Callback() {

			@Override
			public void onFailure(Call call, IOException e) {
				// TODO Auto-generated method stub
				System.out.println("onFailure: " + e.getMessage());// get failure if exception
			}

			@Override
			public void onResponse(Call call, Response response) throws IOException {
				// TODO Auto-generated method stub
				try {
					System.out.println("Data after decrytion: " + Decrypt(response.body().string(), cKey));
				} catch (Exception e) {
					System.out.println(e.toString());
//					e.printStackTrace();
				}
			}
		});
	}

	private static class TrustAllHostnameVerifier implements HostnameVerifier {
		@Override
		public boolean verify(String hostname, SSLSession session) {
			return true;
		}
	}

	private static SSLSocketFactory createSSLSocketFactory() {
		SSLSocketFactory ssfFactory = null;
		try {
			mMyTrustManager = new MyTrustManager();
			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(null, new TrustManager[] { mMyTrustManager }, new SecureRandom());
			ssfFactory = sc.getSocketFactory();
		} catch (Exception ignored) {
			ignored.printStackTrace();
		}

		return ssfFactory;
	}

	public static class MyTrustManager implements X509TrustManager {
		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[0];
		}
	}

	// Encrypt
	public static String Encrypt(String sVal, String sKey) throws Exception {
		SecretKeySpec skeySpec = new SecretKeySpec(decoder.decode(sKey), "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		IvParameterSpec iv = new IvParameterSpec(decoder.decode(ivKey));
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
		return encoder.encodeToString(cipher.doFinal(sVal.getBytes()));
	}

	// Decrypt
	public static String Decrypt(String sVal, String sKey) throws Exception {
		JSONObject jsonObject = new JSONObject(new String(decoder.decode(sVal), "UTF-8"));
		if (!jsonObject.isNull("error_code")) {
			throw new Exception((String) ((JSONObject) jsonObject.get("data")).get("message"));
		} else {
			try {
				ivKey = (String) jsonObject.get("iv");
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
//					e.printStackTrace();
				}
			} catch (Exception ex) {
				System.out.println(e.toString());
//				e.printStackTrace();
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
