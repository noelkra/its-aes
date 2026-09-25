# its-aes
AES Implementation for the IT-Security Lecture

A WPF (.NET 8) application that encrypts and decrypts files with AES, using the
[BouncyCastle](https://www.bouncycastle.org/) `AesEngine` directly and the
[MaterialDesignInXAML](https://github.com/MaterialDesignInXAML/MaterialDesignInXamlToolkit) theme.

```
dotnet run --project src/AesFileCrypt.App
```

## Design

| Requirement | Implementation |
|---|---|
| Key entered in the UI | Passphrase in a password box (with reveal toggle, repeated on encryption). Stretched with PBKDF2-HMAC-SHA256 (600,000 iterations, random 16 byte salt) into the AES key and a separate MAC key. |
| Choice of AES mode | ECB (insecure, demo only), CBC, CTR, CFB, OFB, GCM, EAX, OCB; key size 128/192/256 bit. |
| Same file encrypted twice gives different output | A fresh random salt (→ different key) and a fresh random IV/nonce for every encryption. |
| Modified data is detected | GCM/EAX/OCB: built-in 128 bit tag. All other modes: HMAC-SHA256 over header + ciphertext (encrypt-then-MAC), verified *before* decrypting. The header is authenticated too. Output is written to a temp file and only moved into place on success. |
| Encrypt on one PC, decrypt on another | The file is self-describing: its header holds mode, key size, KDF iterations, salt and IV. The receiver only enters the key. |

### File format

```
"AESF" | version(1) | mode(1) | keyBytes(1) | iterations(4, LE) | saltLen(1) | salt | nonceLen(1) | nonce | ciphertext | tag/HMAC
```

A wrong key and a modified file are indistinguishable by design; both report an authentication failure.

## Layout

- `src/AesFileCrypt.Core` – file format and cipher logic (no UI dependency)
- `src/AesFileCrypt.App` – WPF front end
