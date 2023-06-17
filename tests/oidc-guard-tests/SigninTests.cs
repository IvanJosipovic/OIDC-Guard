using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using oidc_guard;
using System.Net;
using System.Text.Json;
using System.Web;

namespace oidc_guard_tests;

public class SigninTests
{
    [Theory]
    [InlineData("/test", null, HttpStatusCode.Redirect)]
    [InlineData("/test", new[] { "test.com" }, HttpStatusCode.Redirect)]

    [InlineData("https://test.com", null, HttpStatusCode.Redirect)]
    [InlineData("https://subdmain.test.com", null, HttpStatusCode.Redirect)]
    [InlineData("https://subsubdomain.subdmain.test.com", null, HttpStatusCode.Redirect)]

    [InlineData("https://test.com", new[] { "test.com" }, HttpStatusCode.Redirect)]
    [InlineData("https://subdmain.test.com", new[] { ".test.com" }, HttpStatusCode.Redirect)]
    [InlineData("https://subsubdomain.subdmain.test.com", new[] { ".test.com" }, HttpStatusCode.Redirect)]

    [InlineData("https://test.com", new[] { "test2.com", "test.com" }, HttpStatusCode.Redirect)]
    [InlineData("https://subdmain.test.com", new[] { "test2.com", ".test.com" }, HttpStatusCode.Redirect)]
    [InlineData("https://subsubdomain.subdmain.test.com", new[] { "test2.com", ".test.com" }, HttpStatusCode.Redirect)]

    [InlineData("https://bad.com", new[] { "test.com" }, HttpStatusCode.BadRequest)]
    [InlineData("https://subdmain.bad.com", new[] { ".test.com" }, HttpStatusCode.BadRequest)]
    [InlineData("https://subsubdomain.subdmain.bad.com", new[] { ".test.com" }, HttpStatusCode.BadRequest)]

    public async Task Signin(string query, string[]? allowedRedirectDomains, HttpStatusCode status)
    {
        var inMemoryConfigSettings = new Dictionary<string, string?>()
        {
            { "Settings:ClientId", "test" },
            { "Settings:ClientSecret", "secret" },
            { "Settings:OpenIdProviderConfigurationUrl", "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" },
        };

        for (var i = 0; i < allowedRedirectDomains?.Length; i++)
        {
            inMemoryConfigSettings.Add($"Settings:AllowedRedirectDomains:{i}", allowedRedirectDomains[i]);
        }

        var factory = new MyWebApplicationFactory<Program>(inMemoryConfigSettings);

        factory.ClientOptions.AllowAutoRedirect = false;

        var response = await factory.CreateClient().GetAsync($"/signin?rd={HttpUtility.UrlEncode(query)}");

        response.StatusCode.Should().Be(status);
    }
}
