namespace Sreid.Libs.Crypto.Rsa;

/// <summary>
///     A service that provides rsa functionality.
/// </summary>
public interface IRsaService
{
    /// <summary>
    ///     Decrypt the given <paramref name="data" /> using the given <paramref name="privateRsaKey" />.
    /// </summary>
    /// <param name="privateRsaKey">The private rsa key to decrypt the data.</param>
    /// <param name="data">The data that gets decrypted.</param>
    /// <returns>The decrypted data.</returns>
    byte[] Decrypt(string privateRsaKey, byte[] data);

    /// <summary>
    ///     Decrypt the given <paramref name="data" /> using the given <paramref name="privateRsaKey" />.
    /// </summary>
    /// <param name="privateRsaKey">The private rsa key to decrypt the data.</param>
    /// <param name="data">The data that gets decrypted.</param>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>The decrypted data.</returns>
    Task<byte[]> DecryptAsync(string privateRsaKey, byte[] data, CancellationToken cancellationToken);

    /// <summary>
    ///     Encrypt the given <paramref name="data" /> using the given <paramref name="publicRsaKey" />.
    /// </summary>
    /// <param name="publicRsaKey">The public rsa key to encrypt the data.</param>
    /// <param name="data">The data that gets encrypted.</param>
    /// <returns>The encrypted data.</returns>
    byte[] Encrypt(string publicRsaKey, byte[] data);

    /// <summary>
    ///     Encrypt the given <paramref name="data" /> using the given <paramref name="publicRsaKey" />.
    /// </summary>
    /// <param name="publicRsaKey">The public rsa key to encrypt the data.</param>
    /// <param name="data">The data that gets encrypted.</param>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>A <see cref="Task{T}" /> whose result is the encrypted data.</returns>
    Task<byte[]> EncryptAsync(string publicRsaKey, byte[] data, CancellationToken cancellationToken);

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

    /// <summary>
    ///     Validates the given rsa keys.
    /// </summary>
    /// <param name="keys">The keys to validate.</param>
    /// <returns><c>True</c> if the private and public rsa keys match; <c>false</c> otherwise.</returns>
    bool Validate(IRsaKeys keys);

    /// <summary>
    ///     Validates the given rsa keys.
    /// </summary>
    /// <param name="keys">The keys to validate.</param>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>
    ///     A <seealso cref="Task{T}" /> whose result is <c>true</c> if the private and public rsa keys match;
    ///     <c>false</c> otherwise.
    /// </returns>
    Task<bool> ValidateAsync(IRsaKeys keys, CancellationToken cancellationToken);
}
