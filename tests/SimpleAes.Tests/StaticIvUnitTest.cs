using FluentAssertions;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace SimpleAes.Tests
{
    public class StaticIvUnitTest
    {
        private static readonly string key = "h3QMWxG+CO1/DPjEalpMI+wg+MrfLJy+fIswhtreIIo=";
        private static readonly string iv = "Gl3WDwYkSY/AO8POcfCrNQ==";

        [Fact]
        public void CanGenerateKeyText()
        {
            ICryptoGraph crypto = new CryptographAes();
            var (iv, key) = crypto.GenerateKey();
            key.Length.Should().Be(44);
            iv.Length.Should().Be(24);
        }

        [Theory]
        [InlineData("templates/SimpleAes", "templates/SimpleAesEncrypt")]
        public void BytesSyncTest(string path, string expected)
        {
            var data = File.ReadAllBytes(path);
            ICryptoGraph crypto = new CryptographAes();
            var actual = crypto.Encrypt(data, iv, key);
            actual.Should().BeEquivalentTo(File.ReadAllBytes(expected));
            var decrypt = crypto.Decrypt(actual, iv, key);
            decrypt.Should().BeEquivalentTo(data);
        }

        [Theory]
        [InlineData("templates/SimpleAes", "templates/SimpleAesEncrypt")]
        public async Task BytesAsyncTest(string path, string expected)
        {
            var data = File.ReadAllBytes(path);
            ICryptoGraph crypto = new CryptographAes();
            var actual = await crypto.EncryptAsync(data, iv, key);
            actual.Should().BeEquivalentTo(File.ReadAllBytes(expected));
            var decrypt = await crypto.DecryptAsync(actual, iv, key);
            decrypt.Should().BeEquivalentTo(data);
        }

        [Theory]
        [InlineData("templates/SimpleAes", "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")]
        public void StringSyncTest(string path, string expected)
        {
            var text = File.ReadAllText(path);
            ICryptoGraph crypto = new CryptographAes();
            var actual = crypto.Encrypt(text, iv, key);
            actual.Should().Be(expected);
            var decrypt = crypto.Decrypt(actual, iv, key);
            decrypt.Should().Be(text);
        }

        [Theory]
        [InlineData("templates/SimpleAes", "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")]
        public async Task StringAsyncTest(string path, string expected)
        {
            var text = File.ReadAllText(path);
            ICryptoGraph crypto = new CryptographAes();
            var actual = await crypto.EncryptAsync(text, iv, key);
            actual.Should().Be(expected);
            var decrypt = await crypto.DecryptAsync(actual, iv, key);
            decrypt.Should().Be(text);
        }
    }
}
