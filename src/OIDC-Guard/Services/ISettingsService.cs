using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace OIDC_Guard.Services;

public interface ISettingsService
{
    Task<OpenIdConnectConfiguration> GetConfiguration(CancellationToken cancellationToken = default);
}