using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SimpleAes
{
    public interface ICryptoGraph
    {
        (string iv, string key) GenerateKey();
        (string iv, string key) GenerateKey(string ivPassword, string keyPassword);
        Task<string> EncryptAsync(string value, string iv, string key);
        Task<byte[]> EncryptAsync(byte[] data, string iv, string key);
        Task<string> DecryptAsync(string value, string iv, string key);
        Task<byte[]> DecryptAsync(byte[] data, string iv, string key);
    }

    public abstract class CryptographBase
    {
        protected CipherMode Mode = CipherMode.CBC;
        protected PaddingMode Padding = PaddingMode.PKCS7;

        protected async Task<string> EncryptStringAsync(string value, ICryptoTransform encryptor)
        {
            using (var encrypted = new MemoryStream())
            using (var cs = new CryptoStream(encrypted, encryptor, CryptoStreamMode.Write))
            {
                // no using (var writer = new StreamWriter(cs)), direct byte[]
                var buffer = new UTF8Encoding(false).GetBytes(value);
                await cs.WriteAsync(buffer, 0, buffer.Length);
                cs.FlushFinalBlock();
                return encrypted.ToArray().ToBase64();
            }
        }

        protected async Task<byte[]> EncryptBytesAsync(byte[] data, ICryptoTransform encryptor)
        {
            using (var encrypted = new MemoryStream())
            using (var cs = new CryptoStream(encrypted, encryptor, CryptoStreamMode.Write))
            {
                await cs.WriteAsync(data, 0, data.Length);
                cs.FlushFinalBlock();
                return encrypted.ToArray();
            }
        }

        protected async Task<string> DecryptStringAsync(string value, ICryptoTransform decryptor)
        {
            using (var encrypted = new MemoryStream(value.FromBase64()))
            using (var cs = new CryptoStream(encrypted, decryptor, CryptoStreamMode.Read))
            using (var mem = new MemoryStream())
            {
                // no using (var reader = new StreamReader(cs)), direct byte[]
                await cs.CopyToAsync(mem);
                return new UTF8Encoding(false).GetString(mem.ToArray());
            }
        }

        protected async Task<byte[]> DecryptBytesAsync(byte[] data, ICryptoTransform decryptor)
        {
            using (var encrypted = new MemoryStream(data))
            using (var cs = new CryptoStream(encrypted, decryptor, CryptoStreamMode.Read))
            using (var copy = new MemoryStream())
            {
                await cs.CopyToAsync(copy);
                return copy.ToArray();
            }
        }
    }

    public class CryptographAes : CryptographBase, ICryptoGraph
    {
        private readonly int blockSize;
        private readonly int keySize;

        public CryptographAes()
        {
            this.blockSize = 128;
            this.keySize = 256;
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

            return (csp.IV.ToBase64(), csp.Key.ToBase64());
        }

        public (string iv, string key) GenerateKey(string ivPassword, string keyPassword)
        {
            byte[] GenKey(string password, int blockSize)
            {
                var rfc = new Rfc2898DeriveBytes(ivPassword, blockSize / 8);
                var arr = rfc.GetBytes(blockSize / 8);
                return arr;
            }
            return (GenKey(ivPassword, blockSize).ToBase64(), GenKey(keyPassword, blockSize).ToBase64());
        }

        public async Task<string> EncryptAsync(string value, string iv, string key)
        {
            var csp = new AesCryptoServiceProvider()
            {
                BlockSize = blockSize,
                KeySize = keySize,
                Mode = this.Mode,
                Padding = this.Padding,
                IV = iv.FromBase64(), // must be after set Block size
                Key = key.FromBase64(), // must be after set Key size
            };

            using (var encrypted = new MemoryStream())
            using (var encryptor = csp.CreateEncryptor())
            {
                return await EncryptStringAsync(value, encryptor);
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
                IV = iv.FromBase64(), // must be after set Block size
                Key = key.FromBase64(), // must be after set Key size
            };

            using (var encryptor = csp.CreateEncryptor())
            {
                return await EncryptBytesAsync(data, encryptor);
            }
        }

        public async Task<string> DecryptAsync(string value, string iv, string key)
        {
            var plain = string.Empty;
            var csp = new AesCryptoServiceProvider()
            {
                BlockSize = blockSize,
                KeySize = keySize,
                Mode = this.Mode,
                Padding = this.Padding,
                IV = iv.FromBase64(), // must be after set Block size
                Key = key.FromBase64(), // must be after set Key size
            };

            using (var decryptor = csp.CreateDecryptor())
            {
                return await DecryptStringAsync(value, decryptor);
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
                IV = iv.FromBase64(), // must be after set Block size
                Key = key.FromBase64(), // must be after set Key size
            };

            using (var decryptor = csp.CreateDecryptor())
            {
                return await DecryptBytesAsync(data, decryptor);
            }
        }
    }
}
