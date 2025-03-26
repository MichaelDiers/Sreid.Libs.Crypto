namespace Sreid.Libs.Crypto.Tests.Helper;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
///     A dependency injection helper.
/// </summary>
internal static class DependencyHelper
{
    /// <summary>
    ///     Adds the given <paramref name="dependencies" /> to an <seealso cref="IServiceCollection" /> and an instance of
    ///     <typeparamref name="T" />.
    /// </summary>
    /// <typeparam name="T">The type of the requested service.</typeparam>
    /// <param name="dependencies">The dependencies that are injected.</param>
    /// <returns>A service of <typeparamref name="T" />.</returns>
    public static T GetRequiredService<T>(params Func<IServiceCollection, IServiceCollection>[] dependencies)
        where T : notnull
    {
        var services = new ServiceCollection();
        foreach (var dependency in dependencies)
        {
            dependency(services);
        }

        var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<T>();
    }
}
