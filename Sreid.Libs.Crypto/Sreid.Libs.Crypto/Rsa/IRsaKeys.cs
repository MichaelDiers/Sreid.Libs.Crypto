namespace Sreid.Libs.Crypto.Rsa;

/// <summary>
///     Describes a rsa key pair.
/// </summary>
public interface IRsaKeys
{
    /// <summary>
    ///     Gets the private rsa key in pem format.
    /// </summary>
    string PrivateKey { get; }

    /// <summary>
    ///     Gets the public rsa key in pem format.
    /// </summary>
    string PublicKey { get; }
}
