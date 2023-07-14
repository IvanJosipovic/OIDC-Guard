﻿using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using oidc_guard;

namespace oidc_guard_tests.Infra;

internal static class AuthTestsHelpers
{
    public static HttpClient GetClient(Action<Settings>? settingsAction = null, bool allowAutoRedirect = false)
    {
        IdentityModelEventSource.ShowPII = true;

        var settings = new Settings()
        {
            ClientId = FakeJwtIssuer.Audience,
            ClientSecret = "secret",
            OpenIdProviderConfigurationUrl = "https://inmemory.microsoft.com/common/.well-known/openid-configuration",
            Scopes = new[] {"openid", "profile"}
        };

        settingsAction?.Invoke(settings);

        var factory = new MyWebApplicationFactory<Program>(settings)
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices((webHost, services) =>
                {
                    services.AddSingleton<SigninMiddleware>();
                    services.AddTransient<IStartupFilter, SigninStartupFilter>();

                    services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
                    {
                        options.Configuration = null;
                        options.MetadataAddress = null;
                        options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                            settings.OpenIdProviderConfigurationUrl,
                            new OpenIdConnectConfigurationRetriever(),
                            new TestServerDocumentRetriever()
                        );
                    });

                    services.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
                    {
                        options.Configuration = null;
                        options.MetadataAddress = null;
                        options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                            settings.OpenIdProviderConfigurationUrl,
                            new OpenIdConnectConfigurationRetriever(),
                            new TestServerDocumentRetriever()
                        );
                    });
                });
            });

        factory.ClientOptions.AllowAutoRedirect = allowAutoRedirect;

        return factory.CreateDefaultClient();
    }
}