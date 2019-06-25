using FluentAssertions;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace SimpleAes.Tests
{
    public class DynamicIvUnitTest
    {
        private static readonly string key = "h3QMWxG+CO1/DPjEalpMI+wg+MrfLJy+fIswhtreIIo=";

        [Fact]
        public void CanGenerateKeyText()
        {
            ICryptoGraph crypto = new CryptographAes();
            var (iv, key) = crypto.GenerateKey();
            key.Length.Should().Be(44);
            iv.Length.Should().Be(24);
        }

        [Theory]
        [InlineData("templates/SimpleAes")]
        public void BytesSyncTest(string path)
        {
            var data = File.ReadAllBytes(path);
            ICryptoGraph crypto = new CryptographAes();
            var iv = crypto.GenerateIv();
            var actual = crypto.Encrypt(data, iv, key);
            var decrypt = crypto.Decrypt(actual, iv, key);
            decrypt.Should().BeEquivalentTo(data);
        }

        [Theory]
        [InlineData("templates/SimpleAes")]
        public async Task BytesAsyncTest(string path)
        {
            var data = File.ReadAllBytes(path);
            ICryptoGraph crypto = new CryptographAes();
            var iv = crypto.GenerateIv();
            var actual = await crypto.EncryptAsync(data, iv, key);
            var decrypt = await crypto.DecryptAsync(actual, iv, key);
            decrypt.Should().BeEquivalentTo(data);
        }

        [Theory]
        [InlineData("templates/SimpleAes")]
        public void StringSyncTest(string path)
        {
            var text = File.ReadAllText(path);
            ICryptoGraph crypto = new CryptographAes();
            var iv = crypto.GenerateIv();
            var actual = crypto.Encrypt(text, iv, key);
            var decrypt = crypto.Decrypt(actual, iv, key);
            decrypt.Should().Be(text);
        }

        [Theory]
        [InlineData("templates/SimpleAes")]
        public async Task StringAsyncTest(string path)
        {
            var text = File.ReadAllText(path);
            ICryptoGraph crypto = new CryptographAes();
            var iv = crypto.GenerateIv();
            var actual = await crypto.EncryptAsync(text, iv, key);
            var decrypt = await crypto.DecryptAsync(actual, iv, key);
            decrypt.Should().Be(text);
        }
    }
}
