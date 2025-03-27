namespace Sreid.Libs.Crypto.Aes;

using System.Security.Cryptography;

/// <summary>
///     A service that provides aes functionality.
/// </summary>
/// <param name="aesOptions">The aes algorithm options.</param>
/// <seealso cref="IAesService" />
internal class AesService(AesOptions aesOptions) : IAesService
{
    /// <summary>
    ///     The maximum supported length of <seealso cref="SymmetricAlgorithm.IV" />.
    /// </summary>
    private const int MaxAesIvLength = 256;

    /// <summary>
    ///     Decrypt the given <paramref name="data" /> using the given <paramref name="aesKey" />.
    /// </summary>
    /// <param name="aesKey">The aes key to decrypt the data.</param>
    /// <param name="data">The data that gets decrypted.</param>
    /// <returns>The decrypted data.</returns>
    public byte[] Decrypt(byte[] aesKey, byte[] data)
    {
        using var memoryStream = new MemoryStream(data);

        var ivLength = memoryStream.ReadByte();
        var iv = new byte[ivLength];
        if (memoryStream.Read(iv) != ivLength)
        {
            throw new InvalidOperationException($"{nameof(data)} is invalid.");
        }

        using var aes = Aes.Create();
        aes.Padding = aesOptions.PaddingMode;
        aes.KeySize = aesOptions.AesKeySizeInBits;
        aes.Key = aesKey;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();

        using var cryptoStream = new CryptoStream(
            memoryStream,
            decryptor,
            CryptoStreamMode.Read);

        using var decryptedStream = new MemoryStream();
        cryptoStream.CopyTo(decryptedStream);
        return decryptedStream.ToArray();
    }

    /// <summary>
    ///     Decrypt the given <paramref name="data" /> using the given <paramref name="aesKey" />.
    /// </summary>
    /// <param name="aesKey">The aes key to decrypt the data.</param>
    /// <param name="data">The data that gets decrypted.</param>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>A <see cref="Task{T}" /> whose result is the decrypted data.</returns>
    public async Task<byte[]> DecryptAsync(byte[] aesKey, byte[] data, CancellationToken cancellationToken)
    {
        using var memoryStream = new MemoryStream(data);

        var ivLength = memoryStream.ReadByte();
        var iv = new byte[ivLength];
        if (await memoryStream.ReadAsync(
                iv,
                cancellationToken) !=
            ivLength)
        {
            throw new InvalidOperationException($"{nameof(data)} is invalid.");
        }

        using var aes = Aes.Create();
        aes.Padding = aesOptions.PaddingMode;
        aes.KeySize = aesOptions.AesKeySizeInBits;
        aes.Key = aesKey;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();

        await using var cryptoStream = new CryptoStream(
            memoryStream,
            decryptor,
            CryptoStreamMode.Read);

        using var decryptedStream = new MemoryStream();
        await cryptoStream.CopyToAsync(
            decryptedStream,
            cancellationToken);
        return decryptedStream.ToArray();
    }

    /// <summary>
    ///     Encrypt the given <paramref name="data" /> using the given <paramref name="aesKey" />.
    /// </summary>
    /// <param name="aesKey">The aes key to encrypt the data.</param>
    /// <param name="data">The data that gets encrypted.</param>
    /// <returns>The encrypted data.</returns>
    public byte[] Encrypt(byte[] aesKey, byte[] data)
    {
        using var aes = Aes.Create();
        aes.Padding = aesOptions.PaddingMode;
        aes.KeySize = aesOptions.AesKeySizeInBits;
        aes.Key = aesKey;

        aes.GenerateIV();
        var iv = aes.IV;

        if (iv.Length >= AesService.MaxAesIvLength)
        {
            throw new NotSupportedException($"Length of aes iv larger than {AesService.MaxAesIvLength}: {iv.Length}");
        }

        using var encryptedStream = new MemoryStream();
        encryptedStream.WriteByte((byte) iv.Length);
        encryptedStream.Write(
            iv,
            0,
            iv.Length);

        using var encryptor = aes.CreateEncryptor();
        using (var cryptoStream = new CryptoStream(
                   encryptedStream,
                   encryptor,
                   CryptoStreamMode.Write))
        {
            cryptoStream.Write(data);
        }

        return encryptedStream.ToArray();
    }

    /// <summary>
    ///     Encrypt the given <paramref name="data" /> using the given <paramref name="aesKey" />.
    /// </summary>
    /// <param name="aesKey">The aes key to encrypt the data.</param>
    /// <param name="data">The data that gets encrypted.</param>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>A <see cref="Task{T}" /> whose result is the encrypted data.</returns>
    public async Task<byte[]> EncryptAsync(byte[] aesKey, byte[] data, CancellationToken cancellationToken)
    {
        using var aes = Aes.Create();
        aes.Padding = aesOptions.PaddingMode;
        aes.KeySize = aesOptions.AesKeySizeInBits;
        aes.Key = aesKey;

        aes.GenerateIV();
        var iv = aes.IV;

        if (iv.Length >= AesService.MaxAesIvLength)
        {
            throw new NotSupportedException($"Length of aes iv larger than {AesService.MaxAesIvLength}: {iv.Length}");
        }

        using var encryptedStream = new MemoryStream();
        encryptedStream.WriteByte((byte) iv.Length);
        await encryptedStream.WriteAsync(
            iv,
            0,
            iv.Length,
            cancellationToken);

        using var encryptor = aes.CreateEncryptor();
        await using (var cryptoStream = new CryptoStream(
                         encryptedStream,
                         encryptor,
                         CryptoStreamMode.Write))
        {
            await cryptoStream.WriteAsync(
                data,
                cancellationToken);
        }

        return encryptedStream.ToArray();
    }

    /// <summary>
    ///     Generates a new aes key.
    /// </summary>
    /// <returns>The generated aes key.</returns>
    public byte[] GenerateAesKey()
    {
        using var aes = Aes.Create();
        aes.Padding = aesOptions.PaddingMode;
        aes.KeySize = aesOptions.AesKeySizeInBits;

        aes.GenerateKey();

        return aes.Key;
    }

    /// <summary>
    ///     Generates a new aes key.
    /// </summary>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>A <see cref="Task{T}" /> whose result is the generated aes key.</returns>
    public async Task<byte[]> GenerateAesKeyAsync(CancellationToken cancellationToken)
    {
        return await Task.Run(
            this.GenerateAesKey,
            cancellationToken);
    }

    /// <summary>
    ///     Validates the given aes key.
    /// </summary>
    /// <param name="aesKey">The key to validate.</param>
    /// <returns><c>True</c> if the aes key is valid; <c>false</c> otherwise.</returns>
    public bool Validate(byte[] aesKey)
    {
        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        try
        {
            var encrypted = this.Encrypt(
                aesKey,
                data);

            var decrypted = this.Decrypt(
                aesKey,
                encrypted);

            return data.Length == decrypted.Length &&
            Enumerable.Range(
                    0,
                    data.Length)
                .All(index => data[index] == decrypted[index]);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    ///     Validates the given aes key.
    /// </summary>
    /// <param name="aesKey">The key to validate.</param>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>
    ///     A <seealso cref="Task{T}" /> whose result is <c>true</c> if the aes key is valid;
    ///     <c>false</c> otherwise.
    /// </returns>
    public async Task<bool> ValidateAsync(byte[] aesKey, CancellationToken cancellationToken)
    {
        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        try
        {
            var encrypted = await this.EncryptAsync(
                aesKey,
                data,
                cancellationToken);

            var decrypted = await this.DecryptAsync(
                aesKey,
                encrypted,
                cancellationToken);

            return data.Length == decrypted.Length &&
            Enumerable.Range(
                    0,
                    data.Length)
                .All(index => data[index] == decrypted[index]);
        }
        catch
        {
            return false;
        }
    }
}
