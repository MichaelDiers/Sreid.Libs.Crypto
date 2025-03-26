namespace Sreid.Libs.Crypto.Tests.Rsa;

using System.Security.Cryptography;
using Sreid.Libs.Crypto.Rsa;

/// <summary>
///     Tests of <see cref="RsaOptions" />
/// </summary>
public class RsaOptionsTests
{
    private const int DefaultKeySizeInBits = 2048;
    private readonly RSAEncryptionPadding defaultRsaEncryptionPadding = RSAEncryptionPadding.OaepSHA512;

    [Fact]
    public void Ctor_Empty()
    {
        var rsaOptions = new RsaOptions();

        Assert.Equal(
            RsaOptionsTests.DefaultKeySizeInBits,
            rsaOptions.KeySizeInBits);
        Assert.Equal(
            this.defaultRsaEncryptionPadding,
            rsaOptions.RsaEncryptionPadding);
    }

    [Fact]
    public void Ctor_KeySizeInBits()
    {
        const int keySizeInBits = RsaOptionsTests.DefaultKeySizeInBits * 2;

        var rsaOptions = new RsaOptions(keySizeInBits);

        Assert.Equal(
            keySizeInBits,
            rsaOptions.KeySizeInBits);
        Assert.Equal(
            this.defaultRsaEncryptionPadding,
            rsaOptions.RsaEncryptionPadding);
    }

    [Fact]
    public void Ctor_KeySizeInBits_RsaEncryptionPadding()
    {
        const int keySizeInBits = RsaOptionsTests.DefaultKeySizeInBits * 2;
        var rsaEncryptionPadding = this.defaultRsaEncryptionPadding == RSAEncryptionPadding.OaepSHA512
            ? RSAEncryptionPadding.OaepSHA1
            : RSAEncryptionPadding.OaepSHA512;

        var rsaOptions = new RsaOptions(
            keySizeInBits,
            rsaEncryptionPadding);

        Assert.Equal(
            keySizeInBits,
            rsaOptions.KeySizeInBits);
        Assert.Equal(
            rsaEncryptionPadding,
            rsaOptions.RsaEncryptionPadding);
    }

    [Fact]
    public void Ctor_RsaEncryptionPadding()
    {
        var rsaEncryptionPadding = this.defaultRsaEncryptionPadding == RSAEncryptionPadding.OaepSHA512
            ? RSAEncryptionPadding.OaepSHA1
            : RSAEncryptionPadding.OaepSHA512;

        var rsaOptions = new RsaOptions(rsaEncryptionPadding: rsaEncryptionPadding);

        Assert.Equal(
            RsaOptionsTests.DefaultKeySizeInBits,
            rsaOptions.KeySizeInBits);
        Assert.Equal(
            rsaEncryptionPadding,
            rsaOptions.RsaEncryptionPadding);
    }
}
