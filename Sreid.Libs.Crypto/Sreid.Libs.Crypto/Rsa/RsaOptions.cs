namespace Sreid.Libs.Crypto.Rsa;

using System.Security.Cryptography;

/// <summary>
///     The rsa algorithm options.
/// </summary>
/// <param name="keySizeInBits">The rsa key size in bits (default: 2048).</param>
/// <param name="rsaEncryptionPadding">
///     Specifies the type of padding the rsa algorithm uses (default:
///     <see cref="RSAEncryptionPadding.OaepSHA512" />).
/// </param>
public class RsaOptions(int keySizeInBits = 2048, RSAEncryptionPadding? rsaEncryptionPadding = null)
{
    /// <summary>
    ///     Gets the rsa key size in bits.
    /// </summary>
    public int KeySizeInBits { get; } = keySizeInBits;

    /// <summary>
    ///     Gets a value that specifies the type of padding the rsa algorithm uses.
    /// </summary>
    public RSAEncryptionPadding RsaEncryptionPadding { get; } = rsaEncryptionPadding ?? RSAEncryptionPadding.OaepSHA512;
}
