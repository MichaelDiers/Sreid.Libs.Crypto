namespace Sreid.Libs.Crypto.Factory;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
///     Extensions of <see cref="IServiceCollection" />.
/// </summary>
public static class FactoryServiceCollectionExtensions
{
    /// <summary>
    ///     Adds the <see cref="ICryptoFactory" /> to the given <paramref name="services" />.
    /// </summary>
    /// <param name="services">The dependencies are added to this <see cref="IServiceCollection" />.</param>
    /// <returns>The given <paramref name="services" />.</returns>
    public static IServiceCollection TryAddCryptoFactory(this IServiceCollection services)
    {
        services.TryAddSingleton<ICryptoFactory, CryptoFactory>();

        return services;
    }

    /// <summary>
    ///     Adds all supported dependencies to the given <see cref="IServiceCollection" />.
    /// </summary>
    /// <param name="services">The dependencies are added to this <see cref="IServiceCollection" />.</param>
    /// <returns>The given <paramref name="services" />.</returns>
    public static IServiceCollection TryAddFactory(this IServiceCollection services)
    {
        services.TryAddCryptoFactory();

        return services;
    }
}
