using System.Security.Cryptography;
using System.Buffers.Binary;
using Geralt;

namespace ChaCha20Poly1305SivDotNet;

// This implementation reuses memory to avoid allocations at the cost of readability
public static class ChaCha20Poly1305Siv
{
    public const int KeySize = 32;
    public const int NonceSize = 16;
    public const int TagSize = 32;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> allZeros = stackalloc byte[ChaCha20.BlockSize]; allZeros.Clear();
        Span<byte> subkeys = stackalloc byte[ChaCha20.BlockSize];
        ChaCha20.Encrypt(subkeys, allZeros, nonce[4..16], key, counter: BinaryPrimitives.ReadUInt32LittleEndian(nonce[..4]));

        Span<byte> poly1305Tag = ciphertext[^Poly1305.TagSize..], poly1305Key = subkeys[..Poly1305.KeySize];
        ComputePoly1305Tag(poly1305Tag, associatedData, plaintext, poly1305Key);

        Span<byte> tag = ciphertext[^TagSize..], tagKey = subkeys[Poly1305.KeySize..];
        ChaCha20.Encrypt(tag, allZeros[..TagSize], poly1305Tag[4..16], tagKey, counter: BinaryPrimitives.ReadUInt32LittleEndian(poly1305Tag[..4]));

        // encKey = subkeys[32..64]
        ChaCha20.Encrypt(subkeys, allZeros, tag[4..16], tagKey, counter: BinaryPrimitives.ReadUInt32LittleEndian(tag[..4]));
        Span<byte> encKey = tagKey;
        ChaCha20.Encrypt(ciphertext[..^TagSize], plaintext, tag[16..28], encKey, counter: 0);
        CryptographicOperations.ZeroMemory(subkeys);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> allZeros = stackalloc byte[ChaCha20.BlockSize]; allZeros.Clear();
        Span<byte> subkeys = stackalloc byte[ChaCha20.BlockSize];
        ChaCha20.Encrypt(subkeys, allZeros, nonce[4..16], key, counter: BinaryPrimitives.ReadUInt32LittleEndian(nonce[..4]));

        ReadOnlySpan<byte> tag = ciphertext[^TagSize..];
        Span<byte> tagKey = subkeys[Poly1305.KeySize..];
        ChaCha20.Encrypt(allZeros, allZeros, tag[4..16], tagKey, counter: BinaryPrimitives.ReadUInt32LittleEndian(tag[..4]));

        Span<byte> encKey = allZeros[Poly1305.KeySize..];
        ChaCha20.Decrypt(plaintext, ciphertext[..^TagSize], tag[16..28], encKey, counter: 0);

        Span<byte> poly1305Tag = allZeros[^Poly1305.TagSize..], poly1305Key = subkeys[..Poly1305.KeySize];
        ComputePoly1305Tag(poly1305Tag, associatedData, plaintext, poly1305Key);

        // computedTag = subkeys[0..32]
        Span<byte> computedTag = poly1305Key;
        // poly1305Tag = allZeros[48..64]
        Span<byte> zeros = allZeros[..TagSize]; zeros.Clear();
        ChaCha20.Encrypt(computedTag, zeros, poly1305Tag[4..16], tagKey, counter: BinaryPrimitives.ReadUInt32LittleEndian(poly1305Tag[..4]));

        bool valid = ConstantTime.Equals(tag, computedTag);
        CryptographicOperations.ZeroMemory(subkeys);
        CryptographicOperations.ZeroMemory(allZeros);
        if (!valid) {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException();
        }
    }

    private static void ComputePoly1305Tag(Span<byte> tag, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> macKey)
    {
        Span<byte> padding = stackalloc byte[16]; padding.Clear();
        using var poly1305 = new IncrementalPoly1305(macKey);
        poly1305.Update(associatedData);
        int remainder = associatedData.Length & 15;
        if (remainder != 0) {
            poly1305.Update(padding[remainder..]);
        }
        poly1305.Update(plaintext);
        remainder = plaintext.Length & 15;
        if (remainder != 0) {
            poly1305.Update(padding[remainder..]);
        }
        BinaryPrimitives.WriteUInt64LittleEndian(padding[..8], (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(padding[8..], (ulong)plaintext.Length);
        poly1305.Update(padding);
        poly1305.Finalize(tag);
    }
}
