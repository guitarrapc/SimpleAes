using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SimpleAes
{
    public interface ICryptoGraph
    {
        /// <summary>
        /// Generate Key and IV
        /// </summary>
        /// <returns></returns>
        (string iv, string key) GenerateKey();
        /// <summary>
        /// Generate Key and IV
        /// </summary>
        /// <param name="ivPassword"></param>
        /// <param name="keyPassword"></param>
        /// <returns></returns>
        (string iv, string key) GenerateKey(string ivPassword, string keyPassword);
        /// <summary>
        /// Generate IV
        /// </summary>
        /// <returns></returns>
        string GenerateIv();
        /// <summary>
        /// Generate IV
        /// </summary>
        /// <param name="ivPassword"></param>
        /// <returns></returns>
        string GenerateIv(string ivPassword);
        /// <summary>
        /// Encrypt with specific iv and key
        /// </summary>
        /// <param name="value"></param>
        /// <param name="iv"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        string Encrypt(string value, string iv, string key);
        /// <summary>
        /// Encrypt with specific iv and key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="iv"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        byte[] Encrypt(byte[] data, string iv, string key);
        /// <summary>
        /// Encrypt with specific iv and key
        /// </summary>
        /// <param name="value"></param>
        /// <param name="iv"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        Task<string> EncryptAsync(string value, string iv, string key);
        /// <summary>
        /// Encrypt with specific iv and key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="iv"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        Task<byte[]> EncryptAsync(byte[] data, string iv, string key);
        /// <summary>
        /// Decrypt with specific iv and key
        /// </summary>
        /// <param name="value"></param>
        /// <param name="iv"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        string Decrypt(string value, string iv, string key);
        /// <summary>
        /// Decrypt with specific iv and key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="iv"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        byte[] Decrypt(byte[] data, string iv, string key);
        /// <summary>
        /// Decrypt with specific iv and key
        /// </summary>
        /// <param name="value"></param>
        /// <param name="iv"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        Task<string> DecryptAsync(string value, string iv, string key);
        /// <summary>
        /// Decrypt with specific iv and key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="iv"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        Task<byte[]> DecryptAsync(byte[] data, string iv, string key);
        /// <summary>
        /// validate encrypt can decrypt
        /// </summary>
        /// <param name="value"></param>
        /// <param name="iv"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        bool ValidateEncrypt(string value, string iv, string key);
        /// <summary>
        /// Decrypt with specific iv and key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="iv"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        bool ValidateEncrypt(byte[] data, string iv, string key);
        /// <summary>
        /// validate encrypt can decrypt
        /// </summary>
        /// <param name="value"></param>
        /// <param name="iv"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        Task<bool> ValidateEncryptAsync(string value, string iv, string key);
        /// <summary>
        /// Decrypt with specific iv and key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="iv"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        Task<bool> ValidateEncryptAsync(byte[] data, string iv, string key);
    }

    public abstract class CryptographBase
    {
        public bool UseBase64Url { get; set; } = false;

        protected CipherMode Mode = CipherMode.CBC;
        protected PaddingMode Padding = PaddingMode.PKCS7;

        public async Task<byte[]> EncryptBytesAsync(byte[] data, ICryptoTransform encryptor)
        {
            using (var encrypted = new MemoryStream())
            using (var cs = new CryptoStream(encrypted, encryptor, CryptoStreamMode.Write))
            {
                await cs.WriteAsync(data, 0, data.Length);
                cs.FlushFinalBlock();
                return encrypted.ToArray();
            }
        }

        public async Task<byte[]> DecryptAsync(byte[] data, ICryptoTransform decryptor)
        {
            using (var encrypted = new MemoryStream(data))
            using (var cs = new CryptoStream(encrypted, decryptor, CryptoStreamMode.Read))
            using (var copy = new MemoryStream())
            {
                await cs.CopyToAsync(copy);
                return copy.ToArray();
            }
        }

        // base64
        protected string ToBase64(byte[] value) => UseBase64Url ? Base64.ToBase64Url(value) : Base64.ToBase64(value);
        protected byte[] FromBase64(string value) => UseBase64Url ? Base64.FromBase64Url(value) : Base64.FromBase64(value);

        internal static class Base64
        {
            public static string ToBase64(byte[] value) => Convert.ToBase64String(value);
            public static byte[] FromBase64(string value) => Convert.FromBase64String(value);
            public static string ToBase64Url(byte[] value) => RemovePadding(Convert.ToBase64String(value)).Replace("+", "-").Replace("/", "_");
            public static byte[] FromBase64Url(string value) => Convert.FromBase64String(PadString(value).Replace("-", "+").Replace("_", "/"));

            private static string RemovePadding(string text) => text.Replace("=", "");
            private static string PadString(string text)
            {
                // shorthand way:
                // base64String.PadRight(base64String.Length + (4 - base64String.Length % 4) % 4, '=');

                var segment = 4;
                var diff = text.Length % segment;

                if (diff == 0) return text;

                var padLength = segment - diff;
                while (padLength-- != 0)
                {
                    text += "=";
                }

                return text;
            }

        }
    }

    public class CryptographAes : CryptographBase, ICryptoGraph
    {
        private readonly int blockSize;
        private readonly int keySize;

        public CryptographAes() : this(128, 256)
        {
        }

        public CryptographAes(int keySize)
        {
            this.blockSize = 128;
            this.keySize = keySize;
        }

        public CryptographAes(int blockSize, int keySize)
        {
            this.blockSize = blockSize;
            this.keySize = keySize;
        }

        public (string iv, string key) GenerateKey()
        {
            var csp = new AesCryptoServiceProvider()
            {
                BlockSize = this.blockSize,
                KeySize = keySize,
                Mode = this.Mode,
                Padding = this.Padding,
            };
            csp.GenerateIV();
            csp.GenerateKey();

            return (ToBase64(csp.IV), ToBase64(csp.Key));
        }

        public (string iv, string key) GenerateKey(string ivPassword, string keyPassword)
        {
            byte[] GenKey(string password, int blockSize)
            {
                var rfc = new Rfc2898DeriveBytes(password, blockSize / 8);
                var arr = rfc.GetBytes(blockSize / 8);
                return arr;
            }
            var iv = GenKey(ivPassword, blockSize);
            var key = GenKey(keyPassword, blockSize);
            return (ToBase64(iv), ToBase64(key));
        }

        public string GenerateIv()
        {
            var csp = new AesCryptoServiceProvider()
            {
                BlockSize = this.blockSize,
                KeySize = keySize,
                Mode = this.Mode,
                Padding = this.Padding,
            };
            csp.GenerateIV();
            return ToBase64(csp.IV);
        }

        public string GenerateIv(string ivPassword)
        {
            byte[] GenKey(string password, int blockSize)
            {
                var rfc = new Rfc2898DeriveBytes(ivPassword, blockSize / 8);
                var arr = rfc.GetBytes(blockSize / 8);
                return arr;
            }
            var iv = GenKey(ivPassword, blockSize);
            return ToBase64(iv);
        }

        public string Encrypt(string value, string iv, string key)
        {
            using (var aes = Aes.Create())
            {
                aes.BlockSize = blockSize;
                aes.KeySize = keySize;
                aes.Mode = this.Mode;
                aes.Padding = this.Padding;
                aes.IV = FromBase64(iv); // must be after set Block size
                aes.Key = FromBase64(key); // must be after set Key size

                using (var entryptor = aes.CreateEncryptor())
                {
                    var data = new UTF8Encoding(false).GetBytes(value);
                    var v = entryptor.TransformFinalBlock(data, 0, data.Length);
                    return ToBase64(v);
                }
            }
        }

        public byte[] Encrypt(byte[] data, string iv, string key)
        {
            using (var aes = Aes.Create())
            {
                aes.BlockSize = blockSize;
                aes.KeySize = keySize;
                aes.Mode = this.Mode;
                aes.Padding = this.Padding;
                aes.IV = FromBase64(iv); // must be after set Block size
                aes.Key = FromBase64(key); // must be after set Key size

                using (var entryptor = aes.CreateEncryptor())
                {
                    var v = entryptor.TransformFinalBlock(data, 0, data.Length);
                    return v;
                }
            }
        }

        public async Task<string> EncryptAsync(string value, string iv, string key)
        {
            var csp = new AesCryptoServiceProvider()
            {
                BlockSize = blockSize,
                KeySize = keySize,
                Mode = this.Mode,
                Padding = this.Padding,
                IV = FromBase64(iv), // must be after set Block size
                Key = FromBase64(key), // must be after set Key size
            };

            using (var encrypted = new MemoryStream())
            using (var encryptor = csp.CreateEncryptor())
            {
                var data = new UTF8Encoding(false).GetBytes(value);
                var encrypt = await EncryptBytesAsync(data, encryptor);
                return ToBase64(encrypt);
            }
        }

        public async Task<byte[]> EncryptAsync(byte[] data, string iv, string key)
        {
            var csp = new AesCryptoServiceProvider()
            {
                BlockSize = blockSize,
                KeySize = keySize,
                Mode = this.Mode,
                Padding = this.Padding,
                IV = FromBase64(iv), // must be after set Block size
                Key = FromBase64(key), // must be after set Key size
            };

            using (var encryptor = csp.CreateEncryptor())
            {
                return await EncryptBytesAsync(data, encryptor);
            }
        }

        public string Decrypt(string value, string iv, string key)
        {
            using (var aes = Aes.Create())
            {
                aes.BlockSize = blockSize;
                aes.KeySize = keySize;
                aes.Mode = this.Mode;
                aes.Padding = this.Padding;
                aes.IV = FromBase64(iv); // must be after set Block size
                aes.Key = FromBase64(key); // must be after set Key size

                using (var decryptor = aes.CreateDecryptor())
                {
                    var data = FromBase64(value);
                    var v = decryptor.TransformFinalBlock(data, 0, data.Length);
                    return ToBase64(v);
                }
            }
        }

        public byte[] Decrypt(byte[] data, string iv, string key)
        {
            using (var aes = Aes.Create())
            {
                aes.BlockSize = blockSize;
                aes.KeySize = keySize;
                aes.Mode = this.Mode;
                aes.Padding = this.Padding;
                aes.IV = FromBase64(iv); // must be after set Block size
                aes.Key = FromBase64(key); // must be after set Key size

                using (var decryptor = aes.CreateDecryptor())
                {
                    var v = decryptor.TransformFinalBlock(data, 0, data.Length);
                    return v;
                }
            }
        }

        public async Task<string> DecryptAsync(string value, string iv, string key)
        {
            var csp = new AesCryptoServiceProvider()
            {
                BlockSize = blockSize,
                KeySize = keySize,
                Mode = this.Mode,
                Padding = this.Padding,
                IV = FromBase64(iv), // must be after set Block size
                Key = FromBase64(key), // must be after set Key size
            };

            using (var decryptor = csp.CreateDecryptor())
            {
                var decrypt = await DecryptAsync(FromBase64(value), decryptor);
                return new UTF8Encoding(false).GetString(decrypt);
            }
        }

        public async Task<byte[]> DecryptAsync(byte[] data, string iv, string key)
        {
            var csp = new AesCryptoServiceProvider()
            {
                BlockSize = blockSize,
                KeySize = keySize,
                Mode = this.Mode,
                Padding = this.Padding,
                IV = FromBase64(iv), // must be after set Block size
                Key = FromBase64(key), // must be after set Key size
            };

            using (var decryptor = csp.CreateDecryptor())
            {
                return await DecryptAsync(data, decryptor);
            }
        }

        public bool ValidateEncrypt(string value, string iv, string key)
        {
            try
            {
                var _ = Decrypt(value, iv, key);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public bool ValidateEncrypt(byte[] data, string iv, string key)
        {
            try
            {
                var _ = Decrypt(data, iv, key);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public async Task<bool> ValidateEncryptAsync(string value, string iv, string key)
        {
            try
            {
                var _ = await DecryptAsync(value, iv, key);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public async Task<bool> ValidateEncryptAsync(byte[] data, string iv, string key)
        {
            try
            {
                var _ = await DecryptAsync(data, iv, key);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
