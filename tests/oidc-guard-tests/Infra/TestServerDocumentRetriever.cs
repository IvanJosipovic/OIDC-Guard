using Microsoft.IdentityModel.Protocols;

namespace oidc_guard_tests.Infra;

public class TestServerDocumentRetriever : IDocumentRetriever
{
    public Task<string> GetDocumentAsync(string address, CancellationToken cancel)
    {
        if (address.Equals("https://inmemory.microsoft.com/common/.well-known/openid-configuration"))
        {
            // https://openid.net/specs/openid-connect-discovery-1_0.html
            var data = $$"""
                    {
                      "authorization_endpoint": "http://localhost/signin-oidc",
                      "token_endpoint": "https://inmemory.microsoft.com/common/oauth2/token",
                      "token_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt", "client_secret_basic"],
                      "jwks_uri": "https://inmemory.microsoft.com/common/discovery/keys",
                      "response_modes_supported": ["query", "fragment", "form_post"],
                      "subject_types_supported": ["pairwise"],
                      "id_token_signing_alg_values_supported": ["RS256"],
                      "end_session_endpoint": "https://inmemory.microsoft.com/common/oauth2/logout",
                      "response_types_supported": ["code", "id_token", "code id_token", "token id_token", "token"],
                      "scopes_supported": ["openid"],
                      "issuer": "{{FakeJwtIssuer.Issuer}}",
                      "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "acr", "amr", "nonce", "email", "given_name", "family_name", "nickname"],
                      "check_session_iframe": "https://inmemory.microsoft.com/common/oauth2/checksession",
                      "userinfo_endpoint": "https://inmemory.microsoft.com/common/openid/userinfo",
                    }
                    """;

            return Task.FromResult(data);
        }
        if (address.Equals("https://inmemory.microsoft.com/common/discovery/keys"))
        {
            //https://datatracker.ietf.org/doc/html/rfc7517
            var keys = $$"""
                    {
                      "keys": [{
                          "kty": "RSA",
                          "kid": "{{FakeJwtIssuer.JsonWebKey.Kid}}",
                          "x5t": "{{FakeJwtIssuer.JsonWebKey.X5t}}",
                          "x5c": ["{{FakeJwtIssuer.JsonWebKey.X5c.First()}}"]
                        }
                      ]
                    }
                    """;

            return Task.FromResult(keys);
        }

        throw new NotImplementedException();
    }
}
