using FluentAssertions;
using Microsoft.Net.Http.Headers;
using oidc_guard;
using oidc_guard_tests.Infra;
using System.Net;
using Xunit;

namespace oidc_guard_tests
{
    public class SkipAuthPreflightTests
    {
        [Fact]
        public async Task SkipAuthPreflight()
        {
            var _client = AuthTestsHelpers.GetClient(x => { x.SkipAuthPreflight = true; });

            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Origin, "localhost");
            _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XOriginalMethod, "OPTIONS");
            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestHeaders, "origin, x-requested-with");
            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestMethod, "DELETE");

            var response = await _client.GetAsync("/auth");
            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task SkipAuthPreflight2()
        {
            var _client = AuthTestsHelpers.GetClient(x => { x.SkipAuthPreflight = true; });

            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Origin, "localhost");
            _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XForwardedMethod, "OPTIONS");
            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestHeaders, "origin, x-requested-with");
            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestMethod, "DELETE");

            var response = await _client.GetAsync("/auth");
            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task SkipAuthPreflightDisabled()
        {
            var _client = AuthTestsHelpers.GetClient(x => { x.SkipAuthPreflight = false; });

            _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XOriginalMethod, "OPTIONS");
            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestHeaders, "origin, x-requested-with");
            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestMethod, "DELETE");

            var response = await _client.GetAsync("/auth");
            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task SkipAuthPreflightMissingMethod()
        {
            var _client = AuthTestsHelpers.GetClient(x => { x.SkipAuthPreflight = true; });

            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Origin, "localhost");
            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestHeaders, "origin, x-requested-with");
            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestMethod, "DELETE");

            var response = await _client.GetAsync("/auth");
            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task SkipAuthPreflightMissingOrigin()
        {
            var _client = AuthTestsHelpers.GetClient(x => { x.SkipAuthPreflight = true; });

            _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XForwardedMethod, "OPTIONS");
            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestHeaders, "origin, x-requested-with");
            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestMethod, "DELETE");

            var response = await _client.GetAsync("/auth");
            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task SkipAuthPreflightMissingRequestHeaders()
        {
            var _client = AuthTestsHelpers.GetClient(x => { x.SkipAuthPreflight = true; });

            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Origin, "localhost");
            _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XOriginalMethod, "OPTIONS");
            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestMethod, "DELETE");

            var response = await _client.GetAsync("/auth");
            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }
}
