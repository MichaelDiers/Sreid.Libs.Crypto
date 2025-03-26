namespace Sreid.Libs.Crypto.Tests.Rsa;

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
    [InlineData(1024)]
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
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(4096)]
    public async Task GenerateRsaKeysAsync(int keySizeInBits)
    {
        var rsaService = this.cryptoFactory.CreateRsaService(new RsaOptions(keySizeInBits));
        var keys = await rsaService.GenerateRsaKeysAsync(TestContext.Current.CancellationToken);

        Assert.False(string.IsNullOrWhiteSpace(keys.PrivateKey));
        Assert.False(string.IsNullOrWhiteSpace(keys.PublicKey));
    }
}
