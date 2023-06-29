using FluentAssertions;
using oidc_guard_tests.Infra;
using System.Net;
using Xunit;

namespace oidc_guard_tests
{
    public class SingInOutTests
    {
        [Fact]
        public async Task SignIn()
        {
            var _client = AuthTestsHelpers.GetClient(allowAutoRedirect: true);

            var response = await _client.GetAsync("/signin?rd=/auth");
            response.StatusCode.Should().Be(HttpStatusCode.Found);

            _client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", response.Headers.GetValues("Set-Cookie"));

            var response2 = await _client.GetAsync(response.Headers.Location);
            response2.StatusCode.Should().Be(HttpStatusCode.Found);
            response2.Headers.Location.Should().Be("/auth");

            _client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", response2.Headers.GetValues("Set-Cookie"));

            var response3 = await _client.GetAsync(response2.Headers.Location);
            response3.StatusCode.Should().Be(HttpStatusCode.OK);

            _client.DefaultRequestHeaders.Clear();

            var response4 = await _client.GetAsync(response2.Headers.Location);
            response4.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task SignOut()
        {
            var _client = AuthTestsHelpers.GetClient(allowAutoRedirect: true);

            var response = await _client.GetAsync("/signin?rd=/auth");
            response.StatusCode.Should().Be(HttpStatusCode.Found);

            _client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", response.Headers.GetValues("Set-Cookie"));

            var response2 = await _client.GetAsync(response.Headers.Location);
            response2.StatusCode.Should().Be(HttpStatusCode.Found);
            response2.Headers.Location.Should().Be("/auth");

            _client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", response2.Headers.GetValues("Set-Cookie"));

            var response3 = await _client.GetAsync(response2.Headers.Location);
            response3.StatusCode.Should().Be(HttpStatusCode.OK);

            var response4 = await _client.GetAsync("/signout?rd=/auth");
            response4.StatusCode.Should().Be(HttpStatusCode.Found);

            _client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", response4.Headers.GetValues("Set-Cookie"));

            var response5 = await _client.GetAsync(response4.Headers.Location);
            response5.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }
    }
}
