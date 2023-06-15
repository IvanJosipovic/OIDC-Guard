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

            var oidc = services.FirstOrDefault(
                d => d.ServiceType ==
                    typeof(OpenIdConnectHandler));
            services.Remove(oidc);

            var settingsObj = new Settings()
            {
                CookieDomain = "localhost",
                CookieName = "oidc-guard"
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