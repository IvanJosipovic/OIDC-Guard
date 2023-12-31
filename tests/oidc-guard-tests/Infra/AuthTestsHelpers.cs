﻿using Microsoft.AspNetCore.Authentication.JwtBearer;
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
                ClientSecret = "secret",
                Scopes = new[] { "openid", "profile" }
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
                        if (string.IsNullOrEmpty(settings.JWT.JWKSUrl))
                        {
                            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
                            {
                                options.MetadataAddress = null;
                                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                                    settings.OpenIdProviderConfigurationUrl,
                                    new OpenIdConnectConfigurationRetriever(),
                                    new TestServerDocumentRetriever()
                                );
                            });
                        }
                        else
                        {
                            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
                            {
                                options.MetadataAddress = null;
                                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                                    settings.JWT.JWKSUrl,
                                    new JwksRetriever(),
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