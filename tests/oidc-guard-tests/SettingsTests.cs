using FluentAssertions;
using oidc_guard;
using oidc_guard_tests.Infra;
using System.Net;
using Xunit;

namespace oidc_guard_tests;

public class SettingsTests
{
    [Fact]
    public async Task SetJSON()
    {
        var _client = AuthTestsHelpers.GetClient(x => x.LogFormat = LogFormat.JSON, allowAutoRedirect: true);

        var response = await _client.GetAsync("/signin?rd=/auth");
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
    }
}
