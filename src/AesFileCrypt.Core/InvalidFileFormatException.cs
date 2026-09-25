namespace AesFileCrypt.Core;

/// <summary>Thrown when a file is not a valid encrypted file produced by this program.</summary>
public sealed class InvalidFileFormatException(string message) : Exception(message);
