using Microsoft.AspNetCore.DataProtection.KeyManagement;
using System.Reflection;

namespace oidc_guard.Services;

public class HostedService : IHostedService
{
    private readonly ILogger<HostedService> _logger;

    private readonly IKeyManager _keymanager;

    public HostedService(ILogger<HostedService> logger, IKeyManager keyManager)
    {
        _logger = logger;
        _keymanager = keyManager;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var versionAttribute = Assembly.GetEntryAssembly()!.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
        _logger.LogInformation("Version: {version}", versionAttribute);

        if (_keymanager is IDeletableKeyManager deletableKeyManager)
        {
            var sixMonthsAgo = DateTimeOffset.UtcNow.AddMonths(-6);

            deletableKeyManager.DeleteKeys(key => key.ExpirationDate < sixMonthsAgo);
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
