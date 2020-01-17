using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// Import 3rd Party Package
using Newtonsoft.Json;

namespace TestAESEncrypt
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            // key, the Merchant Key, is provided by OneWallet, which had encoded by base64 encoding.
            // The merchat should store it in the persistent storage.
            string key = "2KmMsAzSLqe9Q4P+h0hyWw==";

            // The random IV
            var iv = getRandomBase64String();

            var testData = GetTestData();
            string testJsStr = JsonConvert.SerializeObject(testData);

            string encryptedStr = AesCrypt.AESEncrypt(testJsStr, key, iv);

            Console.WriteLine("Original:\n" + testJsStr);
            try
            {
                string decryptedStr = AesCrypt.Decrypt(encryptedStr, key);
                Console.WriteLine("Decryption Data:\n" + decryptedStr);
            }
            catch (Exception ex)
            {
                Console.WriteLine("error message :\n" + ex.Message);
            }
            Console.ReadLine();
        }

        private static string getRandomBase64String()
        {
            Random rand = new Random();
            Byte[] b = new Byte[16];
            rand.NextBytes(b);
            return Convert.ToBase64String(b);
        }

        private static TestData GetTestData()
        {
            var ret = new TestData();
            ret.sh_order_no = "100001";
            ret.order_amount = "0.1";
            ret.order_type = "100";
            ret.bank_code = "KTB";
            ret.created_at = "2020-01-01 00:00:00";
            ret.notify_url = "https://domain.com/callback";
            ret.note = "test";
            return ret;
        }
    }

    /// Test Data Model
    internal struct TestData
    {
        public string sh_order_no;
        public string order_amount;
        public string order_type;
        public string bank_code;
        public string created_at;
        public string notify_url;
        public string note;
    }
}

public class AesCrypt
{
    private struct AesModel
    {
        public string iv;
        public string value;
    }

    /// IV Data Model
    private struct DataModel
    {
        public string iv;
        public string value;
        public string error_code;
        public Data data;
    }

    private struct Data
    {
        public string message;
    }

    /// Encryption
    public static string AESEncrypt(string toEncrypt, string key, string iv)
    {
        byte[] keyArray = Convert.FromBase64String(key);
        byte[] ivArray = Convert.FromBase64String(iv);
        byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes(toEncrypt);

        RijndaelManaged rDel = new RijndaelManaged();
        rDel.KeySize = 128;
        rDel.BlockSize = 128;
        rDel.Key = keyArray;
        rDel.IV = ivArray;
        rDel.Mode = CipherMode.CBC;
        rDel.Padding = PaddingMode.PKCS7;

        ICryptoTransform cTransform = rDel.CreateEncryptor();
        byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

        var val = Convert.ToBase64String(resultArray, 0, resultArray.Length);

        var data = new AesModel() { iv = iv, value = val };
        var serialData = JsonConvert.SerializeObject(data);
        var ret = Convert.ToBase64String(UTF8Encoding.UTF8.GetBytes(serialData));
        return ret;
    }

    /// Decryption
    public static string Decrypt(string encryptedStr, string KeyString)
    {
        var encoding = new UTF8Encoding();
        string jsStr = encoding.GetString(Convert.FromBase64String(encryptedStr));
        var dataModel = JsonConvert.DeserializeObject<DataModel>(jsStr);

        if (dataModel.error_code != null)
        {
            var message = dataModel.data.message;
            throw new System.ArgumentException(message);
        }
        else
        {
            return AESDecrypt(dataModel.iv, dataModel.value, KeyString);
        }
    }

    static private string AESDecrypt(string iv, string value, string key)
    {
        var sRet = "";
        byte[] cypher = Convert.FromBase64String(value);
        var Key = Convert.FromBase64String(key);
        var IV = Convert.FromBase64String(iv);

        using (var rj = new RijndaelManaged())
        {
            try
            {
                rj.Padding = PaddingMode.PKCS7;
                rj.Mode = CipherMode.CBC;
                rj.KeySize = 128;
                rj.BlockSize = 128;
                rj.Key = Key;
                rj.IV = IV;

                if (cypher == null)
                    return null;

                var ms = new MemoryStream(cypher);

                using (var cs = new CryptoStream(ms, rj.CreateDecryptor(Key, IV), CryptoStreamMode.Read))
                {
                    using (var sr = new StreamReader(cs))
                    {
                        var tmp = sr.ReadLine();
                        while (tmp != null)
                        {
                            sRet = sRet.Length > 0 ? (sRet + "\n" + tmp) : tmp;
                            tmp = sr.ReadLine();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("DecryptRJ128 Error:" + e.ToString());
            }
            finally
            {
                rj.Clear();
            }
        }

        return sRet;
    }
}
