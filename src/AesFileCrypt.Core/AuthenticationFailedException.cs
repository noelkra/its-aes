namespace AesFileCrypt.Core;

/// <summary>Thrown when the integrity check fails: wrong key or the data was modified.</summary>
public sealed class AuthenticationFailedException()
    : Exception("Authentication failed: the key is wrong or the file has been modified.");
