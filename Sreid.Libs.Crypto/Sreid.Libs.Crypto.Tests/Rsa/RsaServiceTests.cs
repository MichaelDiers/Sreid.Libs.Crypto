namespace Sreid.Libs.Crypto.Tests.Rsa;

using System.Security.Cryptography;
using Moq;
using Sreid.Libs.Crypto.Factory;
using Sreid.Libs.Crypto.Rsa;
using Sreid.Libs.Crypto.Tests.Helper;

/// <summary>
///     Tests of <seealso cref="IRsaService" />.
/// </summary>
public class RsaServiceTests
{
    private readonly ICryptoFactory cryptoFactory =
        DependencyHelper.GetRequiredService<ICryptoFactory>(FactoryServiceCollectionExtensions.TryAddCryptoFactory);

    [Theory]
    [InlineData(2048)]
    [InlineData(4096)]
    public void Decrypt(int keySizeInBits)
    {
        var rsaService = this.cryptoFactory.CreateRsaService(new RsaOptions(keySizeInBits));
        var keys = rsaService.GenerateRsaKeys();

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        var encrypted = rsaService.Encrypt(
            keys.PublicKey,
            data);

        var decrypted = rsaService.Decrypt(
            keys.PrivateKey,
            encrypted);

        Assert.True(
            data.Length == decrypted.Length &&
            Enumerable.Range(
                    0,
                    data.Length)
                .All(index => data[index] == decrypted[index]));
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(4096)]
    public async Task DecryptAsync(int keySizeInBits)
    {
        var rsaService = this.cryptoFactory.CreateRsaService(new RsaOptions(keySizeInBits));
        var keys = await rsaService.GenerateRsaKeysAsync(TestContext.Current.CancellationToken);

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        var encrypted = await rsaService.EncryptAsync(
            keys.PublicKey,
            data,
            TestContext.Current.CancellationToken);

        var decrypted = await rsaService.DecryptAsync(
            keys.PrivateKey,
            encrypted,
            TestContext.Current.CancellationToken);

        Assert.True(
            data.Length == decrypted.Length &&
            Enumerable.Range(
                    0,
                    data.Length)
                .All(index => data[index] == decrypted[index]));
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(4096)]
    public void Encrypt(int keySizeInBits)
    {
        var rsaService = this.cryptoFactory.CreateRsaService(new RsaOptions(keySizeInBits));
        var keys = rsaService.GenerateRsaKeys();

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        rsaService.Encrypt(
            keys.PublicKey,
            data);
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(4096)]
    public async Task EncryptAsync(int keySizeInBits)
    {
        var rsaService = this.cryptoFactory.CreateRsaService(new RsaOptions(keySizeInBits));
        var keys = await rsaService.GenerateRsaKeysAsync(TestContext.Current.CancellationToken);

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        await rsaService.EncryptAsync(
            keys.PublicKey,
            data,
            TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(4096)]
    public void GenerateRsaKeys(int keySizeInBits)
    {
        var rsaService = this.cryptoFactory.CreateRsaService(new RsaOptions(keySizeInBits));
        var keys = rsaService.GenerateRsaKeys();

        Assert.False(string.IsNullOrWhiteSpace(keys.PrivateKey));
        Assert.False(string.IsNullOrWhiteSpace(keys.PublicKey));
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(4096)]
    public async Task GenerateRsaKeysAsync(int keySizeInBits)
    {
        var rsaService = this.cryptoFactory.CreateRsaService(new RsaOptions(keySizeInBits));
        var keys = await rsaService.GenerateRsaKeysAsync(TestContext.Current.CancellationToken);

        Assert.False(string.IsNullOrWhiteSpace(keys.PrivateKey));
        Assert.False(string.IsNullOrWhiteSpace(keys.PublicKey));
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(4096)]
    public void Validate(int keySizeInBits)
    {
        var rsaService = this.cryptoFactory.CreateRsaService(new RsaOptions(keySizeInBits));
        var keys = rsaService.GenerateRsaKeys();

        Assert.True(rsaService.Validate(keys));
    }

    [Fact]
    public void Validate_ShouldFail_IfKeysIsInvalid()
    {
        var rsaService = this.cryptoFactory.CreateRsaService();

        var keysMock = new Mock<IRsaKeys>();
        keysMock.Setup(keys => keys.PublicKey).Returns("the invalid key");
        keysMock.Setup(keys => keys.PrivateKey).Returns("the invalid key");

        Assert.False(rsaService.Validate(keysMock.Object));
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(4096)]
    public void Validate_ShouldFail_IfKeysMismatch(int keySizeInBits)
    {
        var rsaService = this.cryptoFactory.CreateRsaService(new RsaOptions(keySizeInBits));
        var keys1 = rsaService.GenerateRsaKeys();
        var keys2 = rsaService.GenerateRsaKeys();

        var keysMock = new Mock<IRsaKeys>();
        keysMock.Setup(keys => keys.PublicKey).Returns(keys1.PublicKey);
        keysMock.Setup(keys => keys.PrivateKey).Returns(keys2.PrivateKey);

        Assert.False(rsaService.Validate(keysMock.Object));
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(4096)]
    public async Task ValidateAsync(int keySizeInBits)
    {
        var rsaService = this.cryptoFactory.CreateRsaService(new RsaOptions(keySizeInBits));
        var keys = await rsaService.GenerateRsaKeysAsync(TestContext.Current.CancellationToken);

        Assert.True(
            await rsaService.ValidateAsync(
                keys,
                TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ValidateAsync_ShouldFail_IfKeysIsInvalid()
    {
        var rsaService = this.cryptoFactory.CreateRsaService();

        var keysMock = new Mock<IRsaKeys>();
        keysMock.Setup(keys => keys.PublicKey).Returns("the invalid key");
        keysMock.Setup(keys => keys.PrivateKey).Returns("the invalid key");

        Assert.False(
            await rsaService.ValidateAsync(
                keysMock.Object,
                TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(4096)]
    public async Task ValidateAsync_ShouldFail_IfKeysMismatch(int keySizeInBits)
    {
        var rsaService = this.cryptoFactory.CreateRsaService(new RsaOptions(keySizeInBits));
        var keys1 = await rsaService.GenerateRsaKeysAsync(TestContext.Current.CancellationToken);
        var keys2 = await rsaService.GenerateRsaKeysAsync(TestContext.Current.CancellationToken);

        var keysMock = new Mock<IRsaKeys>();
        keysMock.Setup(keys => keys.PublicKey).Returns(keys1.PublicKey);
        keysMock.Setup(keys => keys.PrivateKey).Returns(keys2.PrivateKey);

        Assert.False(
            await rsaService.ValidateAsync(
                keysMock.Object,
                TestContext.Current.CancellationToken));
    }
}
