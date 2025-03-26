namespace Sreid.Libs.Crypto.Rsa;

using System.Security.Cryptography;

/// <summary>
///     A service that provides rsa functionality.
/// </summary>
/// <seealso cref="IRsaService" />
internal class RsaService(RsaOptions rsaOptions) : IRsaService
{
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
}
