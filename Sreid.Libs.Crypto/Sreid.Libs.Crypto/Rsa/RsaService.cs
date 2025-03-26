namespace Sreid.Libs.Crypto.Rsa;

using System.Security.Cryptography;

/// <summary>
///     A service that provides rsa functionality.
/// </summary>
/// <seealso cref="IRsaService" />
internal class RsaService(RsaOptions rsaOptions) : IRsaService
{
    /// <summary>
    ///     Decrypt the given <paramref name="data" /> using the given <paramref name="privateRsaKey" />.
    /// </summary>
    /// <param name="privateRsaKey">The private rsa key to decrypt the data.</param>
    /// <param name="data">The data that gets decrypted.</param>
    /// <returns>The decrypted data.</returns>
    public byte[] Decrypt(string privateRsaKey, byte[] data)
    {
        using var rsa = RSA.Create();

        rsa.ImportFromPem(privateRsaKey);
        var decrypted = rsa.Decrypt(
            data,
            rsaOptions.RsaEncryptionPadding);

        return decrypted;
    }

    /// <summary>
    ///     Decrypt the given <paramref name="data" /> using the given <paramref name="privateRsaKey" />.
    /// </summary>
    /// <param name="privateRsaKey">The private rsa key to decrypt the data.</param>
    /// <param name="data">The data that gets decrypted.</param>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>The decrypted data.</returns>
    public async Task<byte[]> DecryptAsync(string privateRsaKey, byte[] data, CancellationToken cancellationToken)
    {
        return await Task.Run(
            () => this.Decrypt(
                privateRsaKey,
                data),
            cancellationToken);
    }

    /// <summary>
    ///     Encrypt the given <paramref name="data" /> using the given <paramref name="publicRsaKey" />.
    /// </summary>
    /// <param name="publicRsaKey">The public rsa key to encrypt the data.</param>
    /// <param name="data">The data that gets encrypted.</param>
    /// <returns>The encrypted data.</returns>
    public byte[] Encrypt(string publicRsaKey, byte[] data)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicRsaKey);

        var encrypted = rsa.Encrypt(
            data,
            rsaOptions.RsaEncryptionPadding);

        return encrypted;
    }

    /// <summary>
    ///     Encrypt the given <paramref name="data" /> using the given <paramref name="publicRsaKey" />.
    /// </summary>
    /// <param name="publicRsaKey">The public rsa key to encrypt the data.</param>
    /// <param name="data">The data that gets encrypted.</param>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>A <see cref="Task{T}" /> whose result is the encrypted data.</returns>
    public async Task<byte[]> EncryptAsync(string publicRsaKey, byte[] data, CancellationToken cancellationToken)
    {
        return await Task.Run(
            () => this.Encrypt(
                publicRsaKey,
                data),
            cancellationToken);
    }

    /// <summary>
    ///     Generates a new pair of rsa public and private keys.
    /// </summary>
    /// <returns>The generated rsa key pair.</returns>
    public IRsaKeys GenerateRsaKeys()
    {
        using var rsa = RSA.Create(rsaOptions.KeySizeInBits);

        var privateKey = rsa.ExportRSAPrivateKeyPem();
        var publicKey = rsa.ExportRSAPublicKeyPem();

        return new RsaKeys(
            privateKey,
            publicKey);
    }

    /// <summary>
    ///     Generates a new pair of rsa public and private keys.
    /// </summary>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>A <see cref="Task{T}" /> whose result is the generated rsa key pair.</returns>
    public async Task<IRsaKeys> GenerateRsaKeysAsync(CancellationToken cancellationToken)
    {
        return await Task.Run(
            this.GenerateRsaKeys,
            cancellationToken);
    }

    /// <summary>
    ///     Validates the given rsa keys.
    /// </summary>
    /// <param name="keys">The keys to validate.</param>
    /// <returns><c>True</c> if the private and public rsa keys match; <c>false</c> otherwise.</returns>
    public bool Validate(IRsaKeys keys)
    {
        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        try
        {
            var encrypted = this.Encrypt(
                keys.PublicKey,
                data);

            var decrypted = this.Decrypt(
                keys.PrivateKey,
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
    ///     Validates the given rsa keys.
    /// </summary>
    /// <param name="keys">The keys to validate.</param>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>
    ///     A <seealso cref="Task{T}" /> whose result is <c>true</c> if the private and public rsa keys match;
    ///     <c>false</c> otherwise.
    /// </returns>
    public async Task<bool> ValidateAsync(IRsaKeys keys, CancellationToken cancellationToken)
    {
        return await Task.Run(
            () => this.Validate(keys),
            cancellationToken);
    }
}
