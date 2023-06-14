using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace OIDC_Guard.Services;

public class SettingsService : ISettingsService
{
    private readonly ILogger<SettingsService> _logger;

    private readonly IConfiguration _configuration;

    private readonly IConfigurationRetriever<OpenIdConnectConfiguration> configurationRetriever;

    private OpenIdConnectConfiguration? openIdConnectConfiguration;

    public SettingsService(ILogger<SettingsService> logger, IConfiguration configuration, IConfigurationRetriever<OpenIdConnectConfiguration> configurationRetriever)
    {
        _logger = logger;
        _configuration = configuration;
        this.configurationRetriever = configurationRetriever;
    }

    public async Task<OpenIdConnectConfiguration> GetConfiguration(CancellationToken cancellationToken = new CancellationToken())
    {
        if (openIdConnectConfiguration == null)
        {
            var configEndpoint = _configuration.GetValue<string>("OpenIdProviderConfigurationUrl");

            if (string.IsNullOrEmpty(configEndpoint))
            {
                const string exp = "Environment Variable OpenIdProviderConfigurationUrl is null!";

                _logger.LogCritical(exp);

                throw new Exception(exp);
            }

            _logger.LogInformation("Loading OpenIdConfiguration from: {config}", configEndpoint);

            try
            {
                openIdConnectConfiguration = await configurationRetriever.GetConfigurationAsync(configEndpoint, new HttpDocumentRetriever(), cancellationToken);
            }
            catch (Exception ex)
            {
                var exp = $"Unable to load OpenIdConfiguration from: {configEndpoint}";

                _logger.LogCritical(ex, exp);

                throw new Exception(exp);
            }
        }

        return openIdConnectConfiguration;
    }
}
