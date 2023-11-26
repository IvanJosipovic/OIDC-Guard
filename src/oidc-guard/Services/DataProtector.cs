using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography;

namespace oidc_guard.Services;

public class DataProtector : IDataProtector
{
    private byte[] _key;

    public DataProtector(string secret)
    {
        var keyGenerator = new Rfc2898DeriveBytes(secret, 0, 1, HashAlgorithmName.SHA256);
        _key = keyGenerator.GetBytes(32);
    }

    public IDataProtector CreateProtector(string purpose)
    {
        return this;
    }

    public byte[] Protect(byte[] plaintextBytes)
    {
        using var encryptor = Aes.Create();
        encryptor.Key = _key;
        using var ms = new MemoryStream();
        ms.Write(encryptor.IV, 0, encryptor.IV.Length);
        using (var cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
        {
            cs.Write(plaintextBytes, 0, plaintextBytes.Length);
            cs.FlushFinalBlock();
        }
        return ms.ToArray();
    }

    public byte[] Unprotect(byte[] encryptedBytes)
    {
        using var encryptor = Aes.Create();
        encryptor.Key = _key;
        encryptor.IV = encryptedBytes.Take(16).ToArray();
        using var ms = new MemoryStream();
        using (var cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
        {
            cs.Write(encryptedBytes, 16, encryptedBytes.Length - 16);
            cs.FlushFinalBlock();
        }
        return ms.ToArray();
    }
}
