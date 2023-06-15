using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using oidc_guard;
using WebMotions.Fake.Authentication.JwtBearer;

namespace oidc_guard_tests;

public class CustomWebApplicationFactory<TProgram> : WebApplicationFactory<TProgram> where TProgram : class
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            var settings = services.FirstOrDefault(
                d => d.ServiceType ==
                    typeof(Settings));

            if (settings is not null)
            {
                services.Remove(settings);
            }

            var settingsObj = new Settings()
            {
                CookieDomain = "localhost",
                CookieName = "oidc-guard",
                ClientId = "",
                ClientSecret = "",
                OpenIdProviderConfigurationUrl = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
            };

            services.AddSingleton(settingsObj);

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = FakeJwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = FakeJwtBearerDefaults.AuthenticationScheme;
            }).AddFakeJwtBearer();

            services.AddHealthChecks();
        });
    }
}