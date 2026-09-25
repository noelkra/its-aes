using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace AesFileCrypt.Core;

public static class AesFileCipher
{
    public const int SaltLength = 16;
    public const int DefaultIterations = 600_000;

    private const int MacKeyLength = 32;
    private const int HmacLength = 32;
    private const int AeadTagBits = 128;
    private const int BufferSize = 64 * 1024;

    public static FileHeader ReadHeader(string path)
    {
        using var input = OpenRead(path);
        return FileHeader.Read(input);
    }

    public static void Encrypt(
        string inputPath, string outputPath, string password, AesMode mode, int keySizeBits,
        IProgress<double>? progress = null, CancellationToken cancellationToken = default)
    {
        if (keySizeBits is not (128 or 192 or 256))
            throw new ArgumentOutOfRangeException(nameof(keySizeBits), "AES key size must be 128, 192 or 256 bits.");

        var header = new FileHeader(
            mode,
            keySizeBits / 8,
            DefaultIterations,
            RandomNumberGenerator.GetBytes(SaltLength),
            RandomNumberGenerator.GetBytes(AesModeInfo.NonceLength(mode)));
        var headerBytes = header.ToBytes();

        WriteAtomically(inputPath, outputPath, (input, output) =>
        {
            var (encKey, macKey) = DeriveKeys(password, header);
            try
            {
                var cipher = CreateCipher(mode, forEncryption: true, encKey, header.Nonce, headerBytes);
                using var hmac = AesModeInfo.IsAuthenticated(mode)
                    ? null
                    : IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, macKey);

                output.Write(headerBytes);
                hmac?.AppendData(headerBytes);

                void Sink(byte[] buf, int len)
                {
                    output.Write(buf, 0, len);
                    hmac?.AppendData(buf, 0, len);
                }

                Pump(cipher, input, input.Length, Sink, 0, 1, progress, cancellationToken);

                if (hmac is not null)
                    output.Write(hmac.GetHashAndReset());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encKey);
                CryptographicOperations.ZeroMemory(macKey);
            }
        });
    }

    public static void Decrypt(
        string inputPath, string outputPath, string password,
        IProgress<double>? progress = null, CancellationToken cancellationToken = default)
    {
        WriteAtomically(inputPath, outputPath, (input, output) =>
        {
            var header = FileHeader.Read(input);
            var headerBytes = header.ToBytes();
            long bodyStart = input.Position;
            bool aead = AesModeInfo.IsAuthenticated(header.Mode);

            long bodyLength = input.Length - bodyStart;
            if (bodyLength < (aead ? AeadTagBits / 8 : HmacLength))
                throw new InvalidFileFormatException("The file is truncated.");

            var (encKey, macKey) = DeriveKeys(password, header);
            try
            {
                if (aead)
                {
                    // Ciphertext + tag go through the cipher together; the tag is checked in DoFinal.
                    var cipher = CreateCipher(header.Mode, forEncryption: false, encKey, header.Nonce, headerBytes);
                    Pump(cipher, input, bodyLength, (buf, len) => output.Write(buf, 0, len), 0, 1, progress, cancellationToken);
                }
                else
                {
                    long cipherLength = bodyLength - HmacLength;

                    // Pass 1: verify the MAC over header + ciphertext before decrypting anything.
                    using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, macKey);
                    hmac.AppendData(headerBytes);
                    var buffer = new byte[BufferSize];
                    long done = 0;
                    while (done < cipherLength)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        int read = input.Read(buffer, 0, (int)Math.Min(buffer.Length, cipherLength - done));
                        if (read <= 0) throw new InvalidFileFormatException("The file is truncated.");
                        hmac.AppendData(buffer, 0, read);
                        done += read;
                        progress?.Report(0.5 * done / cipherLength);
                    }

                    var storedMac = new byte[HmacLength];
                    input.ReadExactly(storedMac);
                    if (!CryptographicOperations.FixedTimeEquals(hmac.GetHashAndReset(), storedMac))
                        throw new AuthenticationFailedException();

                    // Pass 2: decrypt.
                    input.Position = bodyStart;
                    var cipher = CreateCipher(header.Mode, forEncryption: false, encKey, header.Nonce, headerBytes);
                    Pump(cipher, input, cipherLength, (buf, len) => output.Write(buf, 0, len), 0.5, 0.5, progress, cancellationToken);
                }
            }
            catch (InvalidCipherTextException)
            {
                throw new AuthenticationFailedException();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encKey);
                CryptographicOperations.ZeroMemory(macKey);
            }
        });
    }

    /// <summary>Feeds <paramref name="length"/> bytes from <paramref name="input"/> through the cipher.</summary>
    private static void Pump(
        IBufferedCipher cipher, Stream input, long length, Action<byte[], int> sink,
        double progressStart, double progressSpan, IProgress<double>? progress, CancellationToken ct)
    {
        var inBuf = new byte[BufferSize];
        var outBuf = new byte[cipher.GetOutputSize(BufferSize) + 64];
        long done = 0;

        while (done < length)
        {
            ct.ThrowIfCancellationRequested();
            int read = input.Read(inBuf, 0, (int)Math.Min(inBuf.Length, length - done));
            if (read <= 0) throw new InvalidFileFormatException("The file is truncated.");
            int produced = cipher.ProcessBytes(inBuf, 0, read, outBuf, 0);
            if (produced > 0) sink(outBuf, produced);
            done += read;
            progress?.Report(progressStart + progressSpan * done / Math.Max(1, length));
        }

        int last = cipher.DoFinal(outBuf, 0);
        if (last > 0) sink(outBuf, last);
        progress?.Report(progressStart + progressSpan);
    }

    private static IBufferedCipher CreateCipher(AesMode mode, bool forEncryption, byte[] key, byte[] nonce, byte[] header)
    {
        var keyParam = new KeyParameter(key);
        IBufferedCipher cipher;
        ICipherParameters parameters = keyParam;

        switch (mode)
        {
            case AesMode.Ecb:
                cipher = new PaddedBufferedBlockCipher(new AesEngine(), new Pkcs7Padding());
                break;
            case AesMode.Cbc:
                cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding());
                parameters = new ParametersWithIV(keyParam, nonce);
                break;
            case AesMode.Ctr:
                cipher = new BufferedBlockCipher(new SicBlockCipher(new AesEngine()));
                parameters = new ParametersWithIV(keyParam, nonce);
                break;
            case AesMode.Cfb:
                cipher = new BufferedBlockCipher(new CfbBlockCipher(new AesEngine(), 128));
                parameters = new ParametersWithIV(keyParam, nonce);
                break;
            case AesMode.Ofb:
                cipher = new BufferedBlockCipher(new OfbBlockCipher(new AesEngine(), 128));
                parameters = new ParametersWithIV(keyParam, nonce);
                break;
            case AesMode.Gcm:
                cipher = new BufferedAeadBlockCipher(new GcmBlockCipher(new AesEngine()));
                parameters = new AeadParameters(keyParam, AeadTagBits, nonce, header);
                break;
            case AesMode.Eax:
                cipher = new BufferedAeadBlockCipher(new EaxBlockCipher(new AesEngine()));
                parameters = new AeadParameters(keyParam, AeadTagBits, nonce, header);
                break;
            case AesMode.Ocb:
                cipher = new BufferedAeadBlockCipher(new OcbBlockCipher(new AesEngine(), new AesEngine()));
                parameters = new AeadParameters(keyParam, AeadTagBits, nonce, header);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mode));
        }

        cipher.Init(forEncryption, parameters);
        return cipher;
    }

    /// <summary>PBKDF2-HMAC-SHA256 → (AES key, MAC key).</summary>
    private static (byte[] EncKey, byte[] MacKey) DeriveKeys(string password, FileHeader header)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("The key must not be empty.", nameof(password));

        // Normalise so the same key typed on a different OS/keyboard layout yields the same bytes.
        var passwordBytes = Encoding.UTF8.GetBytes(password.Normalize(NormalizationForm.FormC));
        var material = Rfc2898DeriveBytes.Pbkdf2(
            passwordBytes, header.Salt, header.Iterations, HashAlgorithmName.SHA256,
            header.KeySizeBytes + MacKeyLength);
        CryptographicOperations.ZeroMemory(passwordBytes);

        var encKey = material[..header.KeySizeBytes];
        var macKey = material[header.KeySizeBytes..];
        CryptographicOperations.ZeroMemory(material);
        return (encKey, macKey);
    }

    private static FileStream OpenRead(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.SequentialScan);

    /// <summary>Writes to a temp file next to the target and only replaces the target on success.</summary>
    private static void WriteAtomically(string inputPath, string outputPath, Action<FileStream, FileStream> work)
    {
        if (Path.GetFullPath(inputPath).Equals(Path.GetFullPath(outputPath), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Input and output file must be different.");

        var tempPath = outputPath + ".tmp";
        try
        {
            using (var input = OpenRead(inputPath))
            using (var output = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize))
            {
                work(input, output);
            }
            File.Move(tempPath, outputPath, overwrite: true);
        }
        catch
        {
            try { File.Delete(tempPath); } catch { /* best effort */ }
            throw;
        }
    }
}
