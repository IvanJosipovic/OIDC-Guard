using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using oidc_guard;
using System.Net;
using System.Web;

namespace oidc_guard_tests;

public class SigninTests
{
    [Theory]
    [InlineData("/test", "", HttpStatusCode.Redirect)]
    [InlineData("https://test.com", "", HttpStatusCode.Redirect)]
    [InlineData("https://subdmain.test.com", "", HttpStatusCode.Redirect)]
    [InlineData("https://subsubdomain.subdmain.test.com", "", HttpStatusCode.Redirect)]

    [InlineData("https://test.com", "test.com", HttpStatusCode.Redirect)]
    [InlineData("https://subdmain.test.com", ".test.com", HttpStatusCode.Redirect)]
    [InlineData("https://subsubdomain.subdmain.test.com", ".test.com", HttpStatusCode.Redirect)]

    [InlineData("https://bad.com", "test.com", HttpStatusCode.BadRequest)]
    [InlineData("https://subdmain.bad.com", ".test.com", HttpStatusCode.BadRequest)]
    [InlineData("https://subsubdomain.subdmain.bad.com", ".test.com", HttpStatusCode.BadRequest)]

    public async Task Signin(string query, string allowedRedirectDomains, HttpStatusCode status)
    {
        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureAppConfiguration(config =>
                {
                    config.Sources.Clear();

                    var inMemoryConfigSettings = new Dictionary<string, string>()
                    {
                        { "Settings:OpenIdProviderConfigurationUrl", "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" },
                        { "Settings:AllowedRedirectDomains", allowedRedirectDomains },
                    };
                    config.AddInMemoryCollection(inMemoryConfigSettings!);
                });

                builder.ConfigureServices((webHost, services) =>
                {
                    var settings = services.First(d => d.ServiceType == typeof(Settings));
                    services.Remove(settings);

                    var settingsCfg = webHost.Configuration.GetSection("Settings").Get<Settings>();
                    services.AddSingleton(settingsCfg!);
                });

                builder.ConfigureTestServices(services =>
                {
                });
            });

        factory.ClientOptions.AllowAutoRedirect = false;

        var response = await factory.CreateClient().GetAsync($"/signin?rd={HttpUtility.UrlEncode(query)}");

        var cont = await response.Content.ReadAsStringAsync();

        response.StatusCode.Should().Be(status);
    }
}
