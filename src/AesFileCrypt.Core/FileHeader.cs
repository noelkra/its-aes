using System.Text;

namespace AesFileCrypt.Core;

/// <summary>
/// Self-describing header at the start of every encrypted file, so the receiving side only needs the key.
/// It is authenticated together with the ciphertext (AEAD associated data, or covered by the HMAC).
///
/// Layout: "AESF" | version(1) | mode(1) | keyBytes(1) | iterations(4, LE) |
///         saltLen(1) | salt | nonceLen(1) | nonce
/// </summary>
public sealed record FileHeader(AesMode Mode, int KeySizeBytes, int Iterations, byte[] Salt, byte[] Nonce)
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("AESF");
    private const byte Version = 1;
    private const int MaxIterations = 10_000_000;
    private const int MinIterations = 1_000;

    public int KeySizeBits => KeySizeBytes * 8;

    public byte[] ToBytes()
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write(Magic);
        w.Write(Version);
        w.Write((byte)Mode);
        w.Write((byte)KeySizeBytes);
        w.Write(Iterations);
        w.Write((byte)Salt.Length);
        w.Write(Salt);
        w.Write((byte)Nonce.Length);
        w.Write(Nonce);
        w.Flush();
        return ms.ToArray();
    }

    /// <summary>Reads and validates a header from the current position of <paramref name="stream"/>.</summary>
    public static FileHeader Read(Stream stream)
    {
        try
        {
            using var r = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);

            if (!r.ReadBytes(Magic.Length).AsSpan().SequenceEqual(Magic))
                throw new InvalidFileFormatException("This is not a file encrypted with this program.");

            if (r.ReadByte() != Version)
                throw new InvalidFileFormatException("Unsupported file format version.");

            var mode = (AesMode)r.ReadByte();
            if (!Enum.IsDefined(mode))
                throw new InvalidFileFormatException("Unknown encryption mode in file header.");

            int keyBytes = r.ReadByte();
            if (keyBytes is not (16 or 24 or 32))
                throw new InvalidFileFormatException("Invalid key size in file header.");

            int iterations = r.ReadInt32();
            if (iterations is < MinIterations or > MaxIterations)
                throw new InvalidFileFormatException("Invalid key derivation parameters in file header.");

            int saltLen = r.ReadByte();
            if (saltLen != AesFileCipher.SaltLength)
                throw new InvalidFileFormatException("Invalid salt length in file header.");
            var salt = r.ReadBytes(saltLen);

            int nonceLen = r.ReadByte();
            if (nonceLen != AesModeInfo.NonceLength(mode))
                throw new InvalidFileFormatException("Invalid IV/nonce length in file header.");
            var nonce = r.ReadBytes(nonceLen);

            if (salt.Length != saltLen || nonce.Length != nonceLen)
                throw new InvalidFileFormatException("The file is truncated.");

            return new FileHeader(mode, keyBytes, iterations, salt, nonce);
        }
        catch (EndOfStreamException)
        {
            throw new InvalidFileFormatException("The file is truncated.");
        }
    }
}
