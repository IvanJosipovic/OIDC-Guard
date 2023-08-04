using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;

namespace oidc_guard.Services;

public class JwksRetriever : IConfigurationRetriever<OpenIdConnectConfiguration>
{
    public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
    {
        if (string.IsNullOrWhiteSpace(address))
            throw LogHelper.LogArgumentNullException(nameof(address));

        if (retriever == null)
            throw LogHelper.LogArgumentNullException(nameof(retriever));

        var openIdConnectConfiguration = new OpenIdConnectConfiguration()
        {
            JwksUri = address,
        };

        LogHelper.LogVerbose("IDX21812: Retrieving json web keys from: '{0}'.", address);
        var keys = await retriever.GetDocumentAsync(address, cancel).ConfigureAwait(false);

        LogHelper.LogVerbose("IDX21813: Deserializing json web keys: '{0}'.", keys);
        openIdConnectConfiguration.JsonWebKeySet = new JsonWebKeySet(keys);

        foreach (var securityKey in openIdConnectConfiguration.JsonWebKeySet.GetSigningKeys())
        {
            openIdConnectConfiguration.SigningKeys.Add(securityKey);
        }

        return openIdConnectConfiguration;
    }
}