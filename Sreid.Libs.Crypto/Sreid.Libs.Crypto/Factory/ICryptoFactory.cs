namespace Sreid.Libs.Crypto.Factory;

using Sreid.Libs.Crypto.Rsa;

/// <summary>
///     A factory that provides crypto algorithms.
/// </summary>
public interface ICryptoFactory
{
    /// <summary>
    ///     Creates a new service that supports rsa.
    /// </summary>
    /// <param name="rsaOptions">The options of the rsa algorithm.</param>
    /// <returns>A new rsa service.</returns>
    IRsaService CreateRsaService(RsaOptions? rsaOptions = null);
}
