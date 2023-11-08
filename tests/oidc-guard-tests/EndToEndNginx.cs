using Ductus.FluentDocker.Commands;
using FluentAssertions;
using IdentityModel.Client;
using oidc_guard_tests.EndToEnd;
using Xunit;

namespace oidc_guard_tests
{
    [Collection(EndToEndFixture.FixtureName)]
    public class EndToEndNginx
    {
        EndToEndFixture fixture;

        public EndToEndNginx(EndToEndFixture fixture)
        {
            this.fixture = fixture;
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
