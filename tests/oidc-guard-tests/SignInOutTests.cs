using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;
using oidc_guard_tests.Infra;
using Shouldly;
using System.Net;
using System.Security.Claims;
using System.Web;
using Xunit;

namespace oidc_guard_tests;

public class SingInOutTests
{
    [Fact]
    public async Task DisableCookie()
    {
        var _client = AuthTestsHelpers.GetClient(x => x.Cookie.Enable = false, allowAutoRedirect: true);

        var response = await _client.GetAsync("/signin?rd=/auth");
        response.StatusCode.ShouldBe(HttpStatusCode.InternalServerError);
    }

    [Fact]
    public async Task SignIn()
    {
        var _client = AuthTestsHelpers.GetClient(allowAutoRedirect: true);

        var response = await _client.GetAsync("/signin?rd=/auth");
        response.StatusCode.ShouldBe(HttpStatusCode.Found);

        _client.DefaultRequestHeaders.Clear();
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Cookie, response.Headers.GetValues("Set-Cookie"));

        var response2 = await _client.GetAsync(response.Headers.Location);
        response2.StatusCode.ShouldBe(HttpStatusCode.Found);
        response2.Headers.Location.ToString().ShouldBe("/auth");

        _client.DefaultRequestHeaders.Clear();
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Cookie, response2.Headers.GetValues("Set-Cookie"));

        var response3 = await _client.GetAsync(response2.Headers.Location);
        response3.StatusCode.ShouldBe(HttpStatusCode.OK);

        _client.DefaultRequestHeaders.Clear();

        var response4 = await _client.GetAsync(response2.Headers.Location);
        response4.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task SignInBadAuthorization()
    {
        var _client = AuthTestsHelpers.GetClient(allowAutoRedirect: true);

        var response = await _client.GetAsync("/signin?rd=/auth");
        response.StatusCode.ShouldBe(HttpStatusCode.Found);

        _client.DefaultRequestHeaders.Clear();
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Cookie, response.Headers.GetValues("Set-Cookie"));
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, "Bearer fake");

        var response2 = await _client.GetAsync(response.Headers.Location);
        response2.StatusCode.ShouldBe(HttpStatusCode.Found);
        response2.Headers.Location.ToString().ShouldBe("/auth");

        _client.DefaultRequestHeaders.Clear();
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Cookie, response2.Headers.GetValues("Set-Cookie"));
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, "Bearer fake");

        var response3 = await _client.GetAsync(response2.Headers.Location);
        response3.StatusCode.ShouldBe(HttpStatusCode.OK);

        _client.DefaultRequestHeaders.Clear();

        var response4 = await _client.GetAsync(response2.Headers.Location);
        response4.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task SignOut()
    {
        var _client = AuthTestsHelpers.GetClient(allowAutoRedirect: true);

        var response = await _client.GetAsync("/signin?rd=/auth");
        response.StatusCode.ShouldBe(HttpStatusCode.Found);

        _client.DefaultRequestHeaders.Clear();
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Cookie, response.Headers.GetValues("Set-Cookie"));

        var response2 = await _client.GetAsync(response.Headers.Location);
        response2.StatusCode.ShouldBe(HttpStatusCode.Found);
        response2.Headers.Location.ToString().ShouldBe("/auth");

        _client.DefaultRequestHeaders.Clear();
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Cookie, response2.Headers.GetValues("Set-Cookie"));

        var response3 = await _client.GetAsync(response2.Headers.Location);
        response3.StatusCode.ShouldBe(HttpStatusCode.OK);

        var response4 = await _client.GetAsync("/signout?rd=/auth");
        response4.StatusCode.ShouldBe(HttpStatusCode.Found);

        _client.DefaultRequestHeaders.Clear();
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Cookie, response4.Headers.GetValues("Set-Cookie"));

        var response5 = await _client.GetAsync(response4.Headers.Location);
        response5.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    public static IEnumerable<object[]> GetAllowedRedirectDomains()
    {
        return new List<object[]>
        {
            new object[]
            {
                "/test", null, HttpStatusCode.Redirect
            },
            new object[]
            {
                "/test", new[] { "test.com" }, HttpStatusCode.Redirect
            },

            new object[]
            {
                "https://test.com", null, HttpStatusCode.Redirect
            },
            new object[]
            {
                "https://subdmain.test.com", null, HttpStatusCode.Redirect
            },
            new object[]
            {
                "https://subsubdomain.subdmain.test.com", null, HttpStatusCode.Redirect
            },

            new object[]
            {
                "https://test.com", new[] { "test.com" }, HttpStatusCode.Redirect
            },
            new object[]
            {
                "https://subdmain.test.com", new[] { ".test.com" }, HttpStatusCode.Redirect
            },
            new object[]
            {
                "https://subsubdomain.subdmain.test.com", new[] { ".test.com" }, HttpStatusCode.Redirect
            },

            new object[]
            {
                "https://test.com", new[] { "test2.com", "test.com" }, HttpStatusCode.Redirect
            },
            new object[]
            {
                "https://subdmain.test.com", new[] { "test2.com", ".test.com" }, HttpStatusCode.Redirect
            },
            new object[]
            {
                "https://subsubdomain.subdmain.test.com", new[] { "test2.com", ".test.com" }, HttpStatusCode.Redirect
            },

            new object[]
            {
                "https://bad.com", new[] { "test.com" }, HttpStatusCode.BadRequest
            },
            new object[]
            {
                "https://subdmain.bad.com", new[] { ".test.com" }, HttpStatusCode.BadRequest
            },
            new object[]
            {
                "https://subsubdomain.subdmain.bad.com", new[] { ".test.com" }, HttpStatusCode.BadRequest
            },

            new object[]
            {
                "https://test.com", new[] { "Test.com" }, HttpStatusCode.Redirect
            },
            new object[]
            {
                "https://subdmain.test.com", new[] { ".Test.com" }, HttpStatusCode.Redirect
            },
        };
    }

    [Theory]
    [MemberData(nameof(GetAllowedRedirectDomains))]
    public async Task SignInAllowedRedirectDomains(string query, string[]? allowedRedirectDomains, HttpStatusCode status)
    {
        var client = AuthTestsHelpers.GetClient(x => x.Cookie.AllowedRedirectDomains = allowedRedirectDomains);

        var response = await client.GetAsync($"/signin?rd={HttpUtility.UrlEncode(query)}");

        response.StatusCode.ShouldBe(status);

        if (status == HttpStatusCode.Found)
        {
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Cookie, response.Headers.GetValues("Set-Cookie"));

            var response2 = await client.GetAsync(response.Headers.Location);
            response2.StatusCode.ShouldBe(HttpStatusCode.Found);
            response2.Headers.Location.ToString().TrimEnd('/').ShouldBe(query);
        }
    }

    [Theory]
    [MemberData(nameof(GetAllowedRedirectDomains))]
    public async Task SignOutAllowedRedirectDomains(string query, string[]? allowedRedirectDomains, HttpStatusCode status)
    {
        var client = AuthTestsHelpers.GetClient(x => x.Cookie.AllowedRedirectDomains = allowedRedirectDomains);

        var response = await client.GetAsync($"/signin?rd=/health");

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Cookie, response.Headers.GetValues("Set-Cookie"));

        var response2 = await client.GetAsync(response.Headers.Location);
        response2.StatusCode.ShouldBe(HttpStatusCode.Found);

        client.DefaultRequestHeaders.Clear();
        client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Cookie, response2.Headers.GetValues("Set-Cookie"));

        var response3 = await client.GetAsync($"/signout?rd={HttpUtility.UrlEncode(query)}");
        response3.StatusCode.ShouldBe(status);
        if (status == HttpStatusCode.Redirect)
        {
            response3.Headers.Location.ToString().TrimEnd('/').ShouldBe(query);
        }
    }

    [Fact]
    public async Task SetHost()
    {
        var _client = AuthTestsHelpers.GetClient(x => { x.Cookie.Host = "fakedomain.com"; x.Cookie.Scheme = "https"; });

        var response = await _client.GetAsync("/signin?rd=/health");
        response.StatusCode.ShouldBe(HttpStatusCode.Found);

        var query = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        var replyUri = new Uri(query["redirect_uri"]);
        replyUri.Host.ShouldBe("fakedomain.com");
        replyUri.Scheme.ShouldBe("https");
    }

    [Fact]
    public async Task SignedInUnauthorized()
    {
        var _client = AuthTestsHelpers.GetClient();

        var claims = new List<Claim>()
        {
            new("username", "test")
        };

        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer.GenerateBearerJwtToken(claims));

        var response = await _client.GetAsync("/signin?rd=/");
        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }
}
