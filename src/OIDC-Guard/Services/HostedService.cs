using System.Reflection;

namespace OIDC_Guard.Services;

public class HostedService : IHostedService
{
    private readonly ILogger<HostedService> _logger;

    private readonly ISettingsService _settingsService;

    public HostedService(ILogger<HostedService> logger, ISettingsService settingsService)
    {
        _logger = logger;
        _settingsService = settingsService;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var versionAttribute = Assembly.GetEntryAssembly()!.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
        _logger.LogInformation("Version: {version}", versionAttribute);
        await _settingsService.GetConfiguration(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
