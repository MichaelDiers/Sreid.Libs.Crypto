namespace Sreid.Libs.Crypto.Aes;

/// <summary>
///     A service that provides aes functionality.
/// </summary>
public interface IAesService
{
    /// <summary>
    ///     Decrypt the given <paramref name="data" /> using the given <paramref name="aesKey" />.
    /// </summary>
    /// <param name="aesKey">The aes key to decrypt the data.</param>
    /// <param name="data">The data that gets decrypted.</param>
    /// <returns>The decrypted data.</returns>
    byte[] Decrypt(byte[] aesKey, byte[] data);

    /// <summary>
    ///     Decrypt the given <paramref name="data" /> using the given <paramref name="aesKey" />.
    /// </summary>
    /// <param name="aesKey">The aes key to decrypt the data.</param>
    /// <param name="data">The data that gets decrypted.</param>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>A <see cref="Task{T}" /> whose result is the decrypted data.</returns>
    Task<byte[]> DecryptAsync(byte[] aesKey, byte[] data, CancellationToken cancellationToken);

    /// <summary>
    ///     Encrypt the given <paramref name="data" /> using the given <paramref name="aesKey" />.
    /// </summary>
    /// <param name="aesKey">The aes key to encrypt the data.</param>
    /// <param name="data">The data that gets encrypted.</param>
    /// <returns>The encrypted data.</returns>
    byte[] Encrypt(byte[] aesKey, byte[] data);

    /// <summary>
    ///     Encrypt the given <paramref name="data" /> using the given <paramref name="aesKey" />.
    /// </summary>
    /// <param name="aesKey">The aes key to encrypt the data.</param>
    /// <param name="data">The data that gets encrypted.</param>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>A <see cref="Task{T}" /> whose result is the encrypted data.</returns>
    Task<byte[]> EncryptAsync(byte[] aesKey, byte[] data, CancellationToken cancellationToken);

    /// <summary>
    ///     Generates a new aes key.
    /// </summary>
    /// <returns>The generated aes key.</returns>
    byte[] GenerateAesKey();

    /// <summary>
    ///     Generates a new aes key.
    /// </summary>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>A <see cref="Task{T}" /> whose result is the generated aes key.</returns>
    Task<byte[]> GenerateAesKeyAsync(CancellationToken cancellationToken);

    /// <summary>
    ///     Validates the given aes key.
    /// </summary>
    /// <param name="aesKey">The key to validate.</param>
    /// <returns><c>True</c> if the aes key is valid; <c>false</c> otherwise.</returns>
    bool Validate(byte[] aesKey);

    /// <summary>
    ///     Validates the given aes key.
    /// </summary>
    /// <param name="aesKey">The key to validate.</param>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>
    ///     A <seealso cref="Task{T}" /> whose result is <c>true</c> if the aes key is valid;
    ///     <c>false</c> otherwise.
    /// </returns>
    Task<bool> ValidateAsync(byte[] aesKey, CancellationToken cancellationToken);
}
