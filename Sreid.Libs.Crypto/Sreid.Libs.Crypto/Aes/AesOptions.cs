namespace Sreid.Libs.Crypto.Aes;

using System.Security.Cryptography;

/// <summary>
///     The aes algorithm options.
/// </summary>
/// <param name="aesKeySizeInBits">The aes key size in bits (default: <see cref="AesKeySizeInBits.KeySize192" />).</param>
/// <param name="paddingMode">
///     Specifies the type of padding the aes algorithm uses (default:
///     <see cref="System.Security.Cryptography.PaddingMode.PKCS7" />).
/// </param>
public class AesOptions(
    AesKeySizeInBits aesKeySizeInBits = AesKeySizeInBits.KeySize192,
    PaddingMode paddingMode = PaddingMode.PKCS7
)
{
    /// <summary>
    ///     Gets the aes key size in bits.
    /// </summary>
    public int AesKeySizeInBits
    {
        get
        {
            return aesKeySizeInBits switch
            {
                Crypto.Aes.AesKeySizeInBits.KeySize128 => 128,
                Crypto.Aes.AesKeySizeInBits.KeySize192 => 192,
                Crypto.Aes.AesKeySizeInBits.KeySize256 => 256,
                _ => throw new ArgumentOutOfRangeException(
                    nameof(aesKeySizeInBits),
                    aesKeySizeInBits,
                    null)
            };
        }
    }

    /// <summary>
    ///     Gets a value that specifies the type of padding the aes algorithm uses.
    /// </summary>
    public PaddingMode PaddingMode { get; } = paddingMode;
}
