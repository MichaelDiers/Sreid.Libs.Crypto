namespace Sreid.Libs.Crypto.Tests.Aes;

using System.Security.Cryptography;
using Sreid.Libs.Crypto.Aes;
using Sreid.Libs.Crypto.Factory;
using Sreid.Libs.Crypto.Tests.Helper;

/// <summary>
///     Tests of <see cref="IAesService" />.
/// </summary>
public class AesServiceTests
{
    private readonly ICryptoFactory cryptoFactory =
        DependencyHelper.GetRequiredService<ICryptoFactory>(FactoryServiceCollectionExtensions.TryAddCryptoFactory);

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public void Decrypt(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesService = this.cryptoFactory.CreateAesService(new AesOptions(aesKeySizeInBits));

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        var aesKey = aesService.GenerateAesKey();

        var encrypted = aesService.Encrypt(
            aesKey,
            data);

        var decrypted = aesService.Decrypt(
            aesKey,
            encrypted);

        Assert.True(
            data.Length == decrypted.Length &&
            Enumerable.Range(
                    0,
                    data.Length)
                .All(index => data[index] == decrypted[index]));
    }

    [Fact]
    public void Decrypt_ShouldFail_DueToInvalidData()
    {
        var aesService = this.cryptoFactory.CreateAesService();

        var data = new byte[4];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        var aesKey = aesService.GenerateAesKey();

        Assert.Throws<InvalidOperationException>(
            () => aesService.Decrypt(
                aesKey,
                data));
    }

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public async Task DecryptAsync(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesService = this.cryptoFactory.CreateAesService(new AesOptions(aesKeySizeInBits));

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        var aesKey = await aesService.GenerateAesKeyAsync(TestContext.Current.CancellationToken);

        var encrypted = await aesService.EncryptAsync(
            aesKey,
            data,
            TestContext.Current.CancellationToken);

        var decrypted = await aesService.DecryptAsync(
            aesKey,
            encrypted,
            TestContext.Current.CancellationToken);

        Assert.True(
            data.Length == decrypted.Length &&
            Enumerable.Range(
                    0,
                    data.Length)
                .All(index => data[index] == decrypted[index]));
    }

    [Fact]
    public async Task DecryptAsync_ShouldFail_DueToInvalidData()
    {
        var aesService = this.cryptoFactory.CreateAesService();

        var data = new byte[4];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        var aesKey = await aesService.GenerateAesKeyAsync(TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => aesService.DecryptAsync(
                aesKey,
                data,
                TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public void Encrypt(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesService = this.cryptoFactory.CreateAesService(new AesOptions(aesKeySizeInBits));

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        var aesKey = aesService.GenerateAesKey();

        var encrypted = aesService.Encrypt(
            aesKey,
            data);

        Assert.NotNull(encrypted);
    }

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public async Task EncryptAsync(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesService = this.cryptoFactory.CreateAesService(new AesOptions(aesKeySizeInBits));

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        var aesKey = await aesService.GenerateAesKeyAsync(TestContext.Current.CancellationToken);

        var encrypted = await aesService.EncryptAsync(
            aesKey,
            data,
            TestContext.Current.CancellationToken);

        Assert.NotNull(encrypted);
    }

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public void GenerateAesKey(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesService = this.cryptoFactory.CreateAesService(new AesOptions(aesKeySizeInBits));

        var aesKey = aesService.GenerateAesKey();

        Assert.NotNull(aesKey);
    }

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public async Task GenerateAesKeyAsync(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesService = this.cryptoFactory.CreateAesService(new AesOptions(aesKeySizeInBits));

        var aesKey = await aesService.GenerateAesKeyAsync(TestContext.Current.CancellationToken);

        Assert.NotNull(aesKey);
    }

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public void Validate(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesService = this.cryptoFactory.CreateAesService(new AesOptions(aesKeySizeInBits));

        var aesKey = aesService.GenerateAesKey();

        Assert.True(aesService.Validate(aesKey));
    }

    [Fact]
    public void Validate_Fails_UsingInvalidKey()
    {
        var aesService = this.cryptoFactory.CreateAesService();

        var aesKey = new byte[]
        {
            1,
            2,
            4
        };

        Assert.False(aesService.Validate(aesKey));
    }

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public async Task ValidateAsync(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesService = this.cryptoFactory.CreateAesService(new AesOptions(aesKeySizeInBits));

        var aesKey = await aesService.GenerateAesKeyAsync(TestContext.Current.CancellationToken);

        Assert.True(
            await aesService.ValidateAsync(
                aesKey,
                TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ValidateAsync_Fails_UsingInvalidKey()
    {
        var aesService = this.cryptoFactory.CreateAesService();

        var aesKey = new byte[]
        {
            1,
            2,
            4
        };

        Assert.False(
            await aesService.ValidateAsync(
                aesKey,
                TestContext.Current.CancellationToken));
    }
}
