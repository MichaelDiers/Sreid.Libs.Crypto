namespace Sreid.Libs.Crypto.Tests.Factory;

using Sreid.Libs.Crypto.Factory;
using Sreid.Libs.Crypto.Tests.Helper;

/// <summary>
///     Tests of <seealso cref="FactoryServiceCollectionExtensions" />.
/// </summary>
public class FactoryServiceCollectionExtensionsTests
{
    [Fact]
    public void TryAddCryptoFactory()
    {
        var factory =
            DependencyHelper.GetRequiredService<ICryptoFactory>(FactoryServiceCollectionExtensions.TryAddCryptoFactory);
        Assert.NotNull(factory);
    }

    [Fact]
    public void TryAddFactory()
    {
        var factory =
            DependencyHelper.GetRequiredService<ICryptoFactory>(FactoryServiceCollectionExtensions.TryAddFactory);
        Assert.NotNull(factory);
    }
}
