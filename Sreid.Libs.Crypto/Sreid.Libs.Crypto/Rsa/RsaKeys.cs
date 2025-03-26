namespace Sreid.Libs.Crypto.Rsa;

/// <summary>
///     Describes a rsa key pair.
/// </summary>
/// <seealso cref="IRsaKeys" />
internal class RsaKeys(string privateKey, string publicKey) : IRsaKeys
{
    /// <summary>
    ///     Gets the private rsa key in pem format.
    /// </summary>
    public string PrivateKey { get; } = privateKey;

    /// <summary>
    ///     Gets the public rsa key in pem format.
    /// </summary>
    public string PublicKey { get; } = publicKey;
}
