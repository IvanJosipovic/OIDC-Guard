using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using oidc_guard.Services;
using Xunit;

namespace oidc_guard_tests;

public class HostedServiceTests
{
    [Fact]
    public async Task Test()
    {
        IServiceCollection services = new ServiceCollection();

        services.AddLogging();
        services.AddSingleton<ILoggerFactory, NullLoggerFactory>();
        services.AddHostedService<HostedService>();

        var serviceProvider = services.BuildServiceProvider();

        var service = serviceProvider.GetService<IHostedService>() as HostedService;

        await service!.StartAsync(CancellationToken.None);

        await service.StopAsync(CancellationToken.None);
    }
}