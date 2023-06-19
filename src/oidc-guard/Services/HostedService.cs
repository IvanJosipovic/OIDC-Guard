using System.Reflection;

namespace oidc_guard.Services;

public class HostedService : IHostedService
{
    private readonly ILogger<HostedService> _logger;

    public HostedService(ILogger<HostedService> logger)
    {
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var versionAttribute = Assembly.GetEntryAssembly()!.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
        _logger.LogInformation("Version: {version}", versionAttribute);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
