namespace Sreid.Libs.Crypto.Factory;

using Sreid.Libs.Crypto.Aes;
using Sreid.Libs.Crypto.Rsa;

/// <summary>
///     A factory that provides crypto algorithms.
/// </summary>
/// <seealso cref="ICryptoFactory" />
internal class CryptoFactory : ICryptoFactory
{
    /// <summary>
    ///     Creates a new service that supports aes.
    /// </summary>
    /// <param name="aesOptions">The options of the aes algorithm.</param>
    /// <returns>A new aes service.</returns>
    public IAesService CreateAesService(AesOptions? aesOptions = null)
    {
        return new AesService(aesOptions ?? new AesOptions());
    }

    /// <summary>
    ///     Creates a new service that supports rsa.
    /// </summary>
    /// <param name="rsaOptions">The options of the rsa algorithm.</param>
    /// <returns>A new rsa service.</returns>
    public IRsaService CreateRsaService(RsaOptions? rsaOptions = null)
    {
        return new RsaService(rsaOptions ?? new RsaOptions());
    }
}
