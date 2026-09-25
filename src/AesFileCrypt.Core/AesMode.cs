namespace AesFileCrypt.Core;

/// <summary>AES block cipher modes of operation supported by the file format.</summary>
public enum AesMode : byte
{
    Ecb = 0,
    Cbc = 1,
    Ctr = 2,
    Cfb = 3,
    Ofb = 4,
    Gcm = 5,
    Eax = 6,
    Ocb = 7,
}

public static class AesModeInfo
{
    public static IReadOnlyList<AesMode> All { get; } = Enum.GetValues<AesMode>();

    /// <summary>
    /// Authenticated (AEAD) modes produce their own authentication tag. All other modes are
    /// protected with an HMAC-SHA256 (encrypt-then-MAC) appended to the file.
    /// </summary>
    public static bool IsAuthenticated(AesMode mode) => mode is AesMode.Gcm or AesMode.Eax or AesMode.Ocb;

    public static int NonceLength(AesMode mode) => mode switch
    {
        AesMode.Ecb => 0,
        AesMode.Gcm or AesMode.Ocb => 12,
        _ => 16,
    };

    public static string DisplayName(AesMode mode) => mode switch
    {
        AesMode.Ecb => "ECB",
        AesMode.Cbc => "CBC",
        AesMode.Ctr => "CTR",
        AesMode.Cfb => "CFB",
        AesMode.Ofb => "OFB",
        AesMode.Gcm => "GCM",
        AesMode.Eax => "EAX",
        AesMode.Ocb => "OCB",
        _ => mode.ToString(),
    };

    public static string Description(AesMode mode) => mode switch
    {
        AesMode.Ecb => "Electronic Codebook. INSECURE: identical plaintext blocks give identical ciphertext blocks, so patterns stay visible. Integrity via HMAC-SHA256.",
        AesMode.Cbc => "Cipher Block Chaining with PKCS#7 padding. Classic mode. Integrity via HMAC-SHA256.",
        AesMode.Ctr => "Counter mode. Turns AES into a stream cipher. Integrity via HMAC-SHA256.",
        AesMode.Cfb => "Cipher Feedback (128 bit). Stream cipher behaviour. Integrity via HMAC-SHA256.",
        AesMode.Ofb => "Output Feedback (128 bit). Stream cipher behaviour. Integrity via HMAC-SHA256.",
        AesMode.Gcm => "Galois/Counter Mode. Authenticated encryption with a built-in 128 bit tag. Recommended.",
        AesMode.Eax => "EAX. Authenticated encryption with a built-in 128 bit tag.",
        AesMode.Ocb => "Offset Codebook. Fast authenticated encryption with a built-in 128 bit tag.",
        _ => string.Empty,
    };
}
