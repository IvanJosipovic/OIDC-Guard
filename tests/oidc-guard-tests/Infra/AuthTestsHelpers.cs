using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using oidc_guard;
using oidc_guard.Services;

namespace oidc_guard_tests.Infra;

public static class AuthTestsHelpers
{
    public static HttpClient GetClient(Action<Settings>? settingsAction = null, bool allowAutoRedirect = false)
    {
        IdentityModelEventSource.ShowPII = true;

        var settings = new Settings()
        {
            Cookie = new()
            {
                ClientId = FakeJwtIssuer.Audience,
                ClientSecret = "secret"
            },
            OpenIdProviderConfigurationUrl = "https://inmemory.microsoft.com/common/.well-known/openid-configuration",
        };

        settingsAction?.Invoke(settings);

        var factory = new MyWebApplicationFactory<Program>(settings)
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices((webHost, services) =>
                {
                    services.AddSingleton<SigninMiddleware>();
                    services.AddTransient<IStartupFilter, SigninStartupFilter>();

                    if (settings.JWT.Enable)
                    {
                        var jwksUrls = !string.IsNullOrEmpty(settings.JWT.JWKSUrl) ? [settings.JWT.JWKSUrl] : settings.JWT.JWKSUrls;

                        if (jwksUrls != null && jwksUrls.Length > 0)
                        {
                            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
                            {
                                options.MetadataAddress = default!;
                                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                                    jwksUrls[0],
                                    new MultiJwksRetriever(jwksUrls),
                                    new TestServerDocumentRetriever()
                                );
                            });
                        }
                        else
                        {
                            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
                            {
                                options.MetadataAddress = default!;
                                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                                    settings.OpenIdProviderConfigurationUrl,
                                    new OpenIdConnectConfigurationRetriever(),
                                    new TestServerDocumentRetriever()
                                );
                            });
                        }
                    }

                    if (settings.Cookie.Enable)
                    {
                        services.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
                        {
                            options.MetadataAddress = null;
                            options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                                settings.OpenIdProviderConfigurationUrl,
                                new OpenIdConnectConfigurationRetriever(),
                                new TestServerDocumentRetriever()
                            );
                        });
                    }
                });
            });

        factory.ClientOptions.AllowAutoRedirect = allowAutoRedirect;

        return factory.CreateDefaultClient();
    }
}