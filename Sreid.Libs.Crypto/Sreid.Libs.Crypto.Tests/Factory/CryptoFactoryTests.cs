﻿namespace Sreid.Libs.Crypto.Tests.Factory;

using System.Security.Cryptography;
using Sreid.Libs.Crypto.Aes;
using Sreid.Libs.Crypto.Factory;
using Sreid.Libs.Crypto.Rsa;
using Sreid.Libs.Crypto.Tests.Helper;

/// <summary>
///     Tests of <seealso cref="ICryptoFactory" />.
/// </summary>
public class CryptoFactoryTests
{
    private readonly ICryptoFactory factory =
        DependencyHelper.GetRequiredService<ICryptoFactory>(FactoryServiceCollectionExtensions.TryAddCryptoFactory);

    [Fact]
    public void CreateAesService_UsingOptions()
    {
        var service = this.factory.CreateAesService(
            new AesOptions(
                AesKeySizeInBits.KeySize256,
                PaddingMode.ISO10126));

        Assert.NotNull(service);
    }

    [Fact]
    public void CreateAesService_WithoutOptions()
    {
        var service = this.factory.CreateAesService();

        Assert.NotNull(service);
    }

    [Fact]
    public void CreateRsaService_UsingOptions()
    {
        var service = this.factory.CreateRsaService(
            new RsaOptions(
                4096,
                RSAEncryptionPadding.OaepSHA1));

        Assert.NotNull(service);
    }

    [Fact]
    public void CreateRsaService_WithoutOptions()
    {
        var service = this.factory.CreateRsaService();

        Assert.NotNull(service);
    }
}
