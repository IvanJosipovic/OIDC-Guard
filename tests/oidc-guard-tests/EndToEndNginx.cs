using FluentAssertions;
using IdentityModel.Client;
using Microsoft.Playwright;
using oidc_guard_tests.EndToEnd;
using System.Text.RegularExpressions;
using Xunit;

namespace oidc_guard_tests
{
    [Collection(EndToEndFixture.FixtureName)]
    public class EndToEndNginx
    {
        readonly EndToEndFixture fixture;

        public EndToEndNginx(EndToEndFixture fixture)
        {
            this.fixture = fixture;

            if (this.fixture.CurrentChart != "nginx")
            {
                Helm.RepoAdd("nginx", "https://kubernetes.github.io/ingress-nginx").Wait();
                Helm.RepoUpdate().Wait();
                Helm.Upgrade("ingress-nginx", "nginx/ingress-nginx", $"--install -f {Path.Combine(".", "EndToEnd", "ingress-nginx-values.yaml")} --namespace ingress-nginx --create-namespace --kube-context kind-{fixture.Name} --wait").Wait();

                this.fixture.CurrentChart = "nginx";
            }
        }

        [Fact]
        public async Task NoAuth()
        {
            var response = await fixture.HttpClient.GetAsync("https://demo-app.test.loc:32443/");
            response.StatusCode.Should().Be(System.Net.HttpStatusCode.Found);
            response.Headers.Location.OriginalString.Should().StartWith("http://oidc-server.oidc-server:32443/connect/authorize?");
        }

        [Fact]
        public async Task JWT()
        {
            var token = await GetToken();

            var request = new HttpRequestMessage(HttpMethod.Get, "https://demo-app.test.loc:32443/");
            request.Headers.Add("Authorization", "Bearer " + token);

            var response = await fixture.HttpClient.SendAsync(request);
            response.StatusCode.Should().Be(System.Net.HttpStatusCode.OK);
            var content = await response.Content.ReadAsStringAsync();
            content.Contains("Welcome to nginx!").Should().BeTrue();
        }

        [Fact]
        public async Task OIDC()
        {
            using var playwright = await Playwright.CreateAsync();

            await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions() { Headless = true });
            var page = await browser.NewPageAsync(new BrowserNewPageOptions() { IgnoreHTTPSErrors = true });

            await page.GotoAsync("https://demo-app.test.loc:32443/");

            await page.WaitForURLAsync(new Regex("^http:\\/\\/oidc-server\\.oidc-server:32443/"));

            await page.GotoAsync(page.Url.Replace("http://", "https://"));

            await page.WaitForURLAsync(new Regex("^https:\\/\\/oidc-server\\.oidc-server:32443/"));

            await page.Locator("#Input_Username").TypeAsync("User1");

            await page.Locator("#Input_Password").TypeAsync("pwd");

            await page.Locator("#Input_Password").PressAsync("Enter");

            await page.WaitForURLAsync(new Regex("^https:\\/\\/demo-app\\.test\\.loc:32443/"));

            var title = await page.TitleAsync();

            title.Should().Be("Welcome to nginx!");
        }

        private async Task<string> GetToken()
        {
            var settings = new ClientCredentialsTokenRequest
            {
                Address = "https://oidc-server.oidc-server:32443/connect/token",

                ClientId = "client-credentials-mock-client",
                ClientSecret = "client-credentials-mock-client-secret",
                Scope = "some-app-scope-1"
            };

            var response = await fixture.HttpClient.RequestClientCredentialsTokenAsync(settings);

            return response.AccessToken;
        }
    }
}
