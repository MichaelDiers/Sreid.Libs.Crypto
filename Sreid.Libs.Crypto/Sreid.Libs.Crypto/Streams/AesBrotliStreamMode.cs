namespace Sreid.Libs.Crypto.Streams;

/// <summary>
///     The supported modes of the <see cref="AesBrotliStream" />.
/// </summary>
public enum AesBrotliStreamMode
{
    /// <summary>
    ///     Compress and encrypt the stream data.
    /// </summary>
    Pack,

    /// <summary>
    ///     Decrypt and decompress the stream data.
    /// </summary>
    Unpack
}
