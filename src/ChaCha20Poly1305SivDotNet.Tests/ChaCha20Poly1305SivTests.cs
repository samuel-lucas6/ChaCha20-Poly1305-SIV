using System.Security.Cryptography;

namespace ChaCha20Poly1305SivDotNet.Tests;

[TestClass]
public class ChaCha20Poly1305SivTests
{
    // https://github.com/C2SP/C2SP/pull/130
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "85ebd6b3a2dbad07d4811283aaf9777acff58bdab40939a13237be73d3ddd73a",
            "",
            "530ee5e3dae7693017d28e5d7c6936ce",
            "1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2",
            ""
        ];
        yield return
        [
            "935fc3675f8b409d4441409418d92f7d7f52af0a00adc07176c998dbdfaa4d06524ea0769635e044a6aaf00327096437613bec8c76eea651dcaccc2fc66087bda224f38ab220208a9471a3e9eec612c2553d8179f1bd1bf7e884fa25336e5f19ef46bb3581245603969b1b11293ad5611608cb0ff82acbd025c9db100311c6628f41ad9ba81a960b8ccd7fdb19c51252e902",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "530ee5e3dae7693017d28e5d7c6936ce",
            "1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2",
            ""
        ];
        yield return
        [
            "00abda8eb9d81e4bbfec468c33175102ca865a9e10bd1af861a205a996c9818993bd0f5957a0a163a1585bf469ca154802b300c78dd873c9a67111d7eeb3b9d3ee7e7ad37db8375ba30031afaaab163057418225f403b4cbdd0cd3dc4024b984462802ec7fb87bd91ff548a13db805695fa94417acff4230861c1ee555cc839fe8b9ccb122fda85b3970d677dc71e8515276",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "85975d0ee263b966a551adab8325ebe3",
            "1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2",
            ""
        ];
        yield return
        [
            "b00fea62ad4a7d06b99ce816e2800bb51ac0a7ad39a216a1131eb23efd2771f824df9ea5773d68d26a83e04a00e81587cf68353157e5b1abd2a99d9d8c50557ae3c6dfcbad6ad1ccee167c24cb049cf11221ffe1f63231efedf89c3e31c549df66281722670ad82a5014b7fa3869f91a9ccc1d54d3476529356000f20919ac9de59d8ed4f39a62225bc689822916b748cab0",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "530ee5e3dae7693017d28e5d7c6936ce",
            "3ef4832df6f83cd761539792c7c34b90fde64ca02d31151fdf924bf2206e37cb",
            ""
        ];
        yield return
        [
            "65047ab0ada975747e1a1737abd6cb0aeb126b8e8f974c6dc0a45e091a4992ad1190080ab2acc2a5a62c9fff72466f7e054d2b4e9474f01d5b200cc6788e0e30351842fc058faee14fe97fe7cee8d0c84e64fa1b55c19e658468d6035376616182d6d09e3066e9318134e4e2bfadfd381256e85b5e838e89c84d2f544f40cd65bcccfe6f4438ed6325a06d301881ec2e90d2",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "530ee5e3dae7693017d28e5d7c6936ce",
            "1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2",
            "50515253c0c1c2c3c4c5c6c7"
        ];
        yield return
        [
            "10287f0d994ca8b920dcede7ce86a29a055ac8e1c0ca14fe651bb363a2af7e039283515c1a67bf9234494025356684abae8325ad5a2f7ce275ac7fa49d88d735",
            "aeadc48d4a2ea7ee06f9f41a6fbcd651ac5df158860e14af1fb0ebbe0a04bab2",
            "530ee5e3dae7693017d28e5d7c6936ce",
            "1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2",
            "2891ec111a27c55b3a6757ff173ef9cfc02bb682bcee4aaa317715b0b7895a58"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [ChaCha20Poly1305Siv.TagSize - 1, 0, ChaCha20Poly1305Siv.NonceSize, ChaCha20Poly1305Siv.KeySize, ChaCha20Poly1305Siv.TagSize];
        yield return [ChaCha20Poly1305Siv.TagSize, 1, ChaCha20Poly1305Siv.NonceSize, ChaCha20Poly1305Siv.KeySize, ChaCha20Poly1305Siv.TagSize];
        yield return [ChaCha20Poly1305Siv.TagSize, 0, ChaCha20Poly1305Siv.NonceSize + 1, ChaCha20Poly1305Siv.KeySize, ChaCha20Poly1305Siv.TagSize];
        yield return [ChaCha20Poly1305Siv.TagSize, 0, ChaCha20Poly1305Siv.NonceSize - 1, ChaCha20Poly1305Siv.KeySize, ChaCha20Poly1305Siv.TagSize];
        yield return [ChaCha20Poly1305Siv.TagSize, 0, ChaCha20Poly1305Siv.NonceSize, ChaCha20Poly1305Siv.KeySize + 1, ChaCha20Poly1305Siv.TagSize];
        yield return [ChaCha20Poly1305Siv.TagSize, 0, ChaCha20Poly1305Siv.NonceSize, ChaCha20Poly1305Siv.KeySize - 1, ChaCha20Poly1305Siv.TagSize];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, ChaCha20Poly1305Siv.KeySize);
        Assert.AreEqual(16, ChaCha20Poly1305Siv.NonceSize);
        Assert.AreEqual(32, ChaCha20Poly1305Siv.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        ChaCha20Poly1305Siv.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20Poly1305Siv.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        ChaCha20Poly1305Siv.Decrypt(p, c, n, k, ad);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new Dictionary<string, byte[]>
        {
            { "c", Convert.FromHexString(ciphertext) },
            { "n", Convert.FromHexString(nonce) },
            { "k", Convert.FromHexString(key) },
            { "ad", Convert.FromHexString(associatedData) }
        };

        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => ChaCha20Poly1305Siv.Decrypt(p, parameters["c"], parameters["n"], parameters["k"], parameters["ad"]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20Poly1305Siv.Decrypt(p, c, n, k, ad));
    }
}
