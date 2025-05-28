using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace oidc_guard.Services;

//public class JwksRetriever : IConfigurationRetriever<OpenIdConnectConfiguration>
//{
//    public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
//    {
//        if (string.IsNullOrWhiteSpace(address))
//            throw LogHelper.LogArgumentNullException(nameof(address));

//        if (retriever == null)
//            throw LogHelper.LogArgumentNullException(nameof(retriever));

//        var openIdConnectConfiguration = new OpenIdConnectConfiguration()
//        {
//            JwksUri = address,
//        };

//        LogHelper.LogVerbose("IDX21812: Retrieving json web keys from: '{0}'.", address);
//        var keys = await retriever.GetDocumentAsync(address, cancel).ConfigureAwait(false);

//        LogHelper.LogVerbose("IDX21813: Deserializing json web keys: '{0}'.", keys);
//        openIdConnectConfiguration.JsonWebKeySet = new JsonWebKeySet(keys);

//        foreach (var securityKey in openIdConnectConfiguration.JsonWebKeySet.GetSigningKeys())
//        {
//            openIdConnectConfiguration.SigningKeys.Add(securityKey);
//        }

//        return openIdConnectConfiguration;
//    }
//}

public class MultiJwksRetriever : IConfigurationRetriever<OpenIdConnectConfiguration>
{
    private string[] urls;

    public MultiJwksRetriever(string[] urls)
    {
        this.urls = urls;
    }

    /// <summary>
    /// Gets the OpenID Connect configuration from multiple URLs.
    /// </summary>
    /// <param name="address">address is ignored</param>
    /// <param name="retriever"></param>
    /// <param name="cancel"></param>
    /// <returns></returns>
    public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
    {
        if (retriever == null)
        {
            throw LogHelper.LogArgumentNullException(nameof(retriever));
        }

        var openIdConnectConfiguration = new OpenIdConnectConfiguration();

        foreach (var url in urls)
        {
            try
            {
                if (LogHelper.IsEnabled(EventLogLevel.Verbose))
                {
                    LogHelper.LogVerbose("Retrieving json web keys from: '{0}'.", url);
                }

                var doc = await retriever.GetDocumentAsync(url, cancel).ConfigureAwait(false);

                if (LogHelper.IsEnabled(EventLogLevel.Verbose))
                {
                    LogHelper.LogVerbose("Recieved json document", doc);
                }

                var JsonWebKeySet = new JsonWebKeySet(doc);

                foreach (var securityKey in JsonWebKeySet.GetSigningKeys())
                {
                    openIdConnectConfiguration.SigningKeys.Add(securityKey);
                }
            }
            catch (Exception ex)
            {
                LogHelper.LogException<Exception>(ex.Message);
            }
        }

        return openIdConnectConfiguration;
    }
}