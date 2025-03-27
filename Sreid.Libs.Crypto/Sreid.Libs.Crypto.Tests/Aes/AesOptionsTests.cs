namespace Sreid.Libs.Crypto.Tests.Aes;

using System.Security.Cryptography;
using Sreid.Libs.Crypto.Aes;

/// <summary>
///     Tests of <seealso cref="AesOptions" />.
/// </summary>
public class AesOptionsTests
{
    [Fact]
    public void Ctor()
    {
        var aesOptions = new AesOptions();

        Assert.Equal(
            192,
            aesOptions.AesKeySizeInBits);
        Assert.Equal(
            PaddingMode.PKCS7,
            aesOptions.PaddingMode);
    }

    [Theory]
    [InlineData(
        AesKeySizeInBits.KeySize128,
        128)]
    [InlineData(
        AesKeySizeInBits.KeySize192,
        192)]
    [InlineData(
        AesKeySizeInBits.KeySize256,
        256)]
    public void Ctor_AesKeySizeInBits(AesKeySizeInBits aesKeySizeInBits, int expectedAesKeySize)
    {
        var aesOptions = new AesOptions(aesKeySizeInBits);

        Assert.Equal(
            expectedAesKeySize,
            aesOptions.AesKeySizeInBits);
        Assert.Equal(
            PaddingMode.PKCS7,
            aesOptions.PaddingMode);
    }

    [Theory]
    [InlineData(
        AesKeySizeInBits.KeySize128,
        128,
        PaddingMode.PKCS7)]
    [InlineData(
        AesKeySizeInBits.KeySize192,
        192,
        PaddingMode.ANSIX923)]
    [InlineData(
        AesKeySizeInBits.KeySize256,
        256,
        PaddingMode.ISO10126)]
    public void Ctor_AesKeySizeInBits_PaddingMode(
        AesKeySizeInBits aesKeySizeInBits,
        int expectedAesKeySize,
        PaddingMode paddingMode
    )
    {
        var aesOptions = new AesOptions(
            aesKeySizeInBits,
            paddingMode);

        Assert.Equal(
            expectedAesKeySize,
            aesOptions.AesKeySizeInBits);
        Assert.Equal(
            paddingMode,
            aesOptions.PaddingMode);
    }

    [Fact]
    public void Ctor_PaddingMode()
    {
        var paddingMode = new AesOptions().PaddingMode != PaddingMode.PKCS7 ? PaddingMode.PKCS7 : PaddingMode.ISO10126;

        var aesOptions = new AesOptions(paddingMode: paddingMode);

        Assert.Equal(
            192,
            aesOptions.AesKeySizeInBits);
        Assert.Equal(
            paddingMode,
            aesOptions.PaddingMode);
    }
}
