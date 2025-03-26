namespace Sreid.Libs.Crypto.Rsa;

/// <summary>
///     A service that provides rsa functionality.
/// </summary>
public interface IRsaService
{
    /// <summary>
    ///     Generates a new pair of rsa public and private keys.
    /// </summary>
    /// <returns>The generated rsa key pair.</returns>
    IRsaKeys GenerateRsaKeys();

    /// <summary>
    ///     Generates a new pair of rsa public and private keys.
    /// </summary>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>A <see cref="Task{T}" /> whose result is the generated rsa key pair.</returns>
    Task<IRsaKeys> GenerateRsaKeysAsync(CancellationToken cancellationToken);
}
