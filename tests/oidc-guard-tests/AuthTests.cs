using FluentAssertions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;
using oidc_guard;
using oidc_guard_tests.Infra;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Xunit;

namespace oidc_guard_tests;

public class AuthTests
{
    [Fact]
    public async Task Unauthorized()
    {
        var _client = AuthTestsHelpers.GetClient();

        var response = await _client.GetAsync("/auth");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    public static IEnumerable<object[]> GetTests()
    {
        return new List<object[]>
        {
            new object[]
            {
                "",
                new List<Claim>(),
                HttpStatusCode.OK
            },
            new object[]
            {
                "?bob=11111111-1111-1111-1111-111111111111",
                new List<Claim>
                {
                    new Claim("bob", "11111111-1111-1111-1111-111111111111")
                },
                HttpStatusCode.OK
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111",
                new List<Claim>
                {
                    new Claim("tid", "11111111-1111-1111-1111-111111111111")
                },
                HttpStatusCode.OK
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&aud=22222222-2222-2222-2222-222222222222",
                new List<Claim>
                {
                    new Claim("tid", "11111111-1111-1111-1111-111111111111"),
                    new Claim("aud", "22222222-2222-2222-2222-222222222222"),
                },
                HttpStatusCode.OK
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&aud=22222222-2222-2222-2222-222222222222&aud=33333333-3333-3333-3333-333333333333",
                new List<Claim>
                {
                    new Claim("tid", "11111111-1111-1111-1111-111111111111"),
                    new Claim("aud", "33333333-3333-3333-3333-333333333333")
                },
                HttpStatusCode.OK
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&aud=22222222-2222-2222-2222-222222222222&aud=33333333-3333-3333-3333-333333333333",
                new List<Claim>
                {
                    new Claim("tid", "11111111-1111-1111-1111-111111111111"),
                    new Claim("aud", "22222222-2222-2222-2222-222222222222"),
                    new Claim("aud", "33333333-3333-3333-3333-333333333333")
                },
                HttpStatusCode.OK
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111",
                new List<Claim>(),
                HttpStatusCode.Unauthorized
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111",
                new List<Claim>
                {
                    new Claim("tid", "22222222-2222-2222-2222-222222222222")
                },
                HttpStatusCode.Unauthorized
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&aud=22222222-2222-2222-2222-222222222222&aud=33333333-3333-3333-3333-333333333333",
                new List<Claim>(),
                HttpStatusCode.Unauthorized
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&aud=22222222-2222-2222-2222-222222222222&aud=33333333-3333-3333-3333-333333333333",
                new List<Claim>
                {
                    new Claim("tid", "")
                },
                HttpStatusCode.Unauthorized
            },
        };
    }

    public static IEnumerable<object[]> GetArrayTests()
    {
        return new List<object[]>
        {
            new object[]
            {
                "?groups=foo",
                new List<Claim>
                {
                    new Claim("groups", "foo"),
                    new Claim("groups", "bar"),
                    new Claim("groups", "baz"),
                },
                HttpStatusCode.OK
            },

            new object[]
            {
                "?groups=bar",
                new List<Claim>
                {
                    new Claim("groups", "foo"),
                    new Claim("groups", "bar"),
                    new Claim("groups", "baz"),
                },
                HttpStatusCode.OK
            },

            new object[]
            {
                "?groups=baz",
                new List<Claim>
                {
                    new Claim("groups", "foo"),
                    new Claim("groups", "bar"),
                    new Claim("groups", "baz"),
                },
                HttpStatusCode.OK
            },

            new object[]
            {
                "?groups=baz",
                new List<Claim>
                {
                    new Claim("groups", "foo"),
                    new Claim("groups", "bar"),
                },
                HttpStatusCode.Unauthorized
            },
        };
    }

    public static IEnumerable<object[]> GetInjectClaimsTests()
    {
        return new List<object[]>
        {
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-claim=tid",
                new List<Claim>
                {
                    new Claim("tid", "11111111-1111-1111-1111-111111111111")
                },
                HttpStatusCode.OK,
                new List<Claim>
                {
                    new Claim("tid", "11111111-1111-1111-1111-111111111111")
                }
            },

            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-claim=tid&inject-claim=aud",
                new List<Claim>
                {
                    new Claim("tid", "11111111-1111-1111-1111-111111111111"),
                    new Claim("aud", "22222222-2222-2222-2222-222222222222"),
                },
                HttpStatusCode.OK,
                new List<Claim>
                {
                    new Claim("tid", "11111111-1111-1111-1111-111111111111"),
                    new Claim("aud", "22222222-2222-2222-2222-222222222222"),
                }
            },

            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-claim=tid,tenant",
                new List<Claim>
                {
                    new Claim("tid", "11111111-1111-1111-1111-111111111111"),
                    new Claim("aud", "22222222-2222-2222-2222-222222222222"),
                },
                HttpStatusCode.OK,
                new List<Claim>
                {
                    new Claim("tenant", "11111111-1111-1111-1111-111111111111")
                }
            },

            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-claim=tid,tenant&inject-claim=aud,audiance",
                new List<Claim>
                {
                    new Claim("tid", "11111111-1111-1111-1111-111111111111"),
                    new Claim("aud", "22222222-2222-2222-2222-222222222222"),
                },
                HttpStatusCode.OK,
                new List<Claim>
                {
                    new Claim("tenant", "11111111-1111-1111-1111-111111111111"),
                    new Claim("audiance", "22222222-2222-2222-2222-222222222222"),
                }
            },

            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-claim=groups",
                new List<Claim>
                {
                    new Claim("tid", "11111111-1111-1111-1111-111111111111"),
                    new Claim("aud", "22222222-2222-2222-2222-222222222222"),
                    new Claim("groups", "admin"),
                    new Claim("groups", "viewer"),
                },
                HttpStatusCode.OK,
                new List<Claim>
                {
                    new Claim("groups", "admin"),
                    new Claim("groups", "viewer"),
                }
            },

            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-claim=group",
                new List<Claim>
                {
                    new Claim("tid", "11111111-1111-1111-1111-111111111111")
                },
                HttpStatusCode.OK
            },

            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-claim=group,group",
                new List<Claim>
                {
                    new Claim("tid", "11111111-1111-1111-1111-111111111111"),
                    new Claim("aud", "22222222-2222-2222-2222-222222222222"),
                },
                HttpStatusCode.OK
            },
        };
    }

    [Theory]
    [MemberData(nameof(GetTests))]
    [MemberData(nameof(GetArrayTests))]
    [MemberData(nameof(GetInjectClaimsTests))]
    public async Task Auth(string query, List<Claim> claims, HttpStatusCode status, List<Claim>? expectedHeaders = null)
    {
        var _client = AuthTestsHelpers.GetClient();

        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer.GenerateBearerJwtToken(claims));

        var response = await _client.GetAsync($"/auth{query}");
        response.StatusCode.Should().Be(status);

        if (expectedHeaders != null)
        {
            foreach (var expectedHeader in expectedHeaders)
            {
                var found = response.Headers.Where(x => x.Key == expectedHeader.Type).SelectMany(x => x.Value).Any(x => x == expectedHeader.Value);
                found.Should().BeTrue();
            }
        }
    }

    [Fact]
    public async Task DisableJWTAuth()
    {
        var _client = AuthTestsHelpers.GetClient(x => x.JWT.Enable = false);

        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer.GenerateBearerJwtToken(new List<Claim>()));

        var response = await _client.GetAsync($"/auth");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    public static IEnumerable<object[]> GetTokenAsQueryParameterTests()
    {
        return new List<object[]>
        {
            new object[] // Token Only in Query String
            {
                "",
                new List<Claim>(),
                HttpStatusCode.OK,
                new Dictionary<string, string>()
                {
                    {CustomHeaderNames.OriginalUrl, $"https://www.example.com?{QueryParameters.AccessToken}={FakeJwtIssuer.GenerateJwtToken(Enumerable.Empty<Claim>())}" }
                }
            },
            new object[] // Bad Token Only in Query String
            {
                "",
                new List<Claim>(),
                HttpStatusCode.Unauthorized,
                new Dictionary<string, string>()
                {
                    {CustomHeaderNames.OriginalUrl, $"https://www.example.com?{QueryParameters.AccessToken}=BAD" }
                }
            },
            new object[] // Bad Token in Query String and Header, Header is used
            {
                "",
                new List<Claim>(),
                HttpStatusCode.OK,
                new Dictionary<string, string>()
                {
                    {CustomHeaderNames.OriginalUrl, $"https://www.example.com?{QueryParameters.AccessToken}=BAD" }
                },
                true
            },
            new object[] // Token in Header and Query String with no Token
            {
                "",
                new List<Claim>(),
                HttpStatusCode.OK,
                new Dictionary<string, string>()
                {
                    {CustomHeaderNames.OriginalUrl, "https://www.example.com" }
                },
                true
            },
            new object[] // Token in Query String with Claim
            {
                "?tid=11111111-1111-1111-1111-111111111111",
                new List<Claim>(),
                HttpStatusCode.OK,
                new Dictionary<string, string>()
                {
                    {CustomHeaderNames.OriginalUrl, $"https://www.example.com?{QueryParameters.AccessToken}={FakeJwtIssuer.GenerateJwtToken(new List<Claim>{new Claim("tid", "11111111-1111-1111-1111-111111111111")})}" }
                },
            },
            new object[] // Token in Query String with Bad Claim
            {
                "?tid=11111111-1111-1111-1111-111111111111",
                new List<Claim>(),
                HttpStatusCode.Unauthorized,
                new Dictionary<string, string>()
                {
                    {CustomHeaderNames.OriginalUrl, $"https://www.example.com?{QueryParameters.AccessToken}={FakeJwtIssuer.GenerateJwtToken(new List<Claim>{new Claim("tid", "22222222-2222-2222-2222-222222222222")})}" }
                },
            },
        };
    }

    [Theory]
    [MemberData(nameof(GetTokenAsQueryParameterTests))]
    public async Task TokenInQueryParamTests(string query, List<Claim> claims, HttpStatusCode status, Dictionary<string, string> requestHeaders, bool addAuthorizationHeader = false)
    {
        var _client = AuthTestsHelpers.GetClient(x => { x.JWT.EnableAccessTokenInQueryParameter = true; });

        foreach (var header in requestHeaders)
        {
            _client.DefaultRequestHeaders.Add(header.Key, header.Value);
        }

        if (addAuthorizationHeader)
        {
            _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer.GenerateBearerJwtToken(claims));
        }

        var response = await _client.GetAsync($"/auth{query}");
        response.StatusCode.Should().Be(status);
    }

    [Fact]
    public async Task Robots()
    {
        var _client = AuthTestsHelpers.GetClient();

        var response = await _client.GetAsync("/robots.txt");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).Should().Be("User-agent: *\r\nDisallow: /");
    }

    [Fact]
    public async Task UserInfo()
    {
        var _client = AuthTestsHelpers.GetClient();

        var claims = new List<Claim>()
        {
            new Claim("username", "test")
        };

        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer.GenerateBearerJwtToken(claims));

        var response = await _client.GetAsync("/userinfo");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await response.Content.ReadFromJsonAsync<JsonDocument>();

        json.RootElement.GetProperty("username").GetString().Should().Be("test");
    }

    [Theory]
    [InlineData("?skip-auth=GET,test", "https://test.com", "GET", HttpStatusCode.OK)]
    [InlineData("?skip-auth=GET,test", "https://test.com", "POST", HttpStatusCode.Unauthorized)]
    [InlineData("?skip-auth=GET,test", "https://bob.com", "GET", HttpStatusCode.Unauthorized)]
    [InlineData("?skip-auth=test", "https://test.com", "GET", HttpStatusCode.OK)]
    [InlineData("?skip-auth=test", "https://bob.com", "GET", HttpStatusCode.Unauthorized)]

    [InlineData("?skip-auth-ne=GET,test", "https://bob.com", "POST", HttpStatusCode.OK)]
    [InlineData("?skip-auth-ne=GET,test", "https://test.com", "GET", HttpStatusCode.Unauthorized)]
    [InlineData("?skip-auth-ne=test", "https://bob.com", "GET", HttpStatusCode.OK)]
    [InlineData("?skip-auth-ne=test", "https://test.com", "GET", HttpStatusCode.Unauthorized)]
    public async Task SkipAuth(string query, string Url, string httpMethod, HttpStatusCode status)
    {
        var _client = AuthTestsHelpers.GetClient();

        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.OriginalUrl, Url);
        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.OriginalMethod, httpMethod);

        var response = await _client.GetAsync($"/auth{query}");
        response.StatusCode.Should().Be(status);
    }

    [Fact]
    public async Task SetHost()
    {
        var _client = AuthTestsHelpers.GetClient(x => { x.Host = "fakedomain.com"; x.Scheme = "https"; });

        var response = await _client.GetAsync("/signin?rd=/health");
        response.StatusCode.Should().Be(HttpStatusCode.Found);

        var query = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        var replyUri = new Uri(query["redirect_uri"]);
        replyUri.Host.Should().Be("fakedomain.com");
        replyUri.Scheme.Should().Be("https");
    }
}
