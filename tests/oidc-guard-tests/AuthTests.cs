using FluentAssertions;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Net.Http.Headers;
using oidc_guard;
using oidc_guard.Services;
using oidc_guard_tests.Infra;
using System.Net;
using System.Net.Http.Headers;
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
        return
        [
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
                HttpStatusCode.Unauthorized,
                new List<KeyValuePair<string, string>>()
                {
                    new(HeaderNames.WWWAuthenticate, "Bearer error=\"invalid_token\", error_description=\"Missing Claim [tid, 11111111-1111-1111-1111-111111111111]\"")
                }
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111",
                new List<Claim>
                {
                    new Claim("tid", "22222222-2222-2222-2222-222222222222")
                },
                HttpStatusCode.Unauthorized,
                new List<KeyValuePair<string, string>>()
                {
                    new(HeaderNames.WWWAuthenticate, "Bearer error=\"invalid_token\", error_description=\"Missing Claim [tid, 11111111-1111-1111-1111-111111111111]\"")
                }
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&aud=22222222-2222-2222-2222-222222222222&aud=33333333-3333-3333-3333-333333333333",
                new List<Claim>(),
                HttpStatusCode.Unauthorized,
                new List<KeyValuePair<string, string>>()
                {
                    new(HeaderNames.WWWAuthenticate, "Bearer error=\"invalid_token\", error_description=\"Missing Claim [tid, 11111111-1111-1111-1111-111111111111]\"")
                }
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&aud=22222222-2222-2222-2222-222222222222&aud=33333333-3333-3333-3333-333333333333",
                new List<Claim>
                {
                    new Claim("tid", "")
                },
                HttpStatusCode.Unauthorized,
                new List<KeyValuePair<string, string>>()
                {
                    new(HeaderNames.WWWAuthenticate, "Bearer error=\"invalid_token\", error_description=\"Missing Claim [tid, 11111111-1111-1111-1111-111111111111]\"")
                }
            },
        ];
    }

    public static IEnumerable<object[]> GetArrayTests()
    {
        return
        [
            new object[]
            {
                "?groups=foo",
                new List<Claim>
                {
                    new("groups", "foo"),
                    new("groups", "bar"),
                    new("groups", "baz"),
                },
                HttpStatusCode.OK
            },

            new object[]
            {
                "?groups=bar",
                new List<Claim>
                {
                    new("groups", "foo"),
                    new("groups", "bar"),
                    new("groups", "baz"),
                },
                HttpStatusCode.OK
            },

            new object[]
            {
                "?groups=baz",
                new List<Claim>
                {
                    new("groups", "foo"),
                    new("groups", "bar"),
                    new("groups", "baz"),
                },
                HttpStatusCode.OK
            },

            new object[]
            {
                "?groups=baz",
                new List<Claim>
                {
                    new("groups", "foo"),
                    new("groups", "bar"),
                },
                HttpStatusCode.Unauthorized
            },
        ];
    }

    public static IEnumerable<object[]> GetInjectClaimsTests()
    {
        return
        [
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-claim=tid",
                new List<Claim>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111")
                },
                HttpStatusCode.OK,
                new List<KeyValuePair<string,string>>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111")
                }
            },

            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-claim=tid&inject-claim=aud2",
                new List<Claim>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111"),
                    new("aud2", "22222222-2222-2222-2222-222222222222"),
                },
                HttpStatusCode.OK,
                new List<KeyValuePair<string,string>>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111"),
                    new("aud2", "22222222-2222-2222-2222-222222222222"),
                }
            },

            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-claim=tid,tenant",
                new List<Claim>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111"),
                    new("aud", "22222222-2222-2222-2222-222222222222"),
                },
                HttpStatusCode.OK,
                new List<KeyValuePair<string,string>>
                {
                    new("tenant", "11111111-1111-1111-1111-111111111111")
                }
            },

            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-claim=tid,tenant&inject-claim=aud2,audiance",
                new List<Claim>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111"),
                    new("aud2", "22222222-2222-2222-2222-222222222222"),
                },
                HttpStatusCode.OK,
                new List<KeyValuePair<string,string>>
                {
                    new("tenant", "11111111-1111-1111-1111-111111111111"),
                    new("audiance", "22222222-2222-2222-2222-222222222222"),
                }
            },

            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-claim=groups",
                new List<Claim>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111"),
                    new("aud", "22222222-2222-2222-2222-222222222222"),
                    new("groups", "admin"),
                    new("groups", "viewer"),
                },
                HttpStatusCode.OK,
                new List<KeyValuePair<string,string>>
                {
                    new("groups", "admin, viewer"),
                }
            },

            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-claim=group",
                new List<Claim>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111")
                },
                HttpStatusCode.OK
            },

            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-claim=group,group",
                new List<Claim>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111"),
                    new("aud", "22222222-2222-2222-2222-222222222222"),
                },
                HttpStatusCode.OK
            },

            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-json-claim=role,gcip,$.firebase.sign_in_attributes.role",
                new List<Claim>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111"),
                    new("gcip", "{\"auth_time\":1553219869,\"email\":\"demo_user@gmail.com\",\"email_verified\":true,\"firebase\":{\"identities\":{\"email\":[\"demo_user@gmail.com\"],\"saml.myProvider\":[\"demo_user@gmail.com\"]},\"sign_in_attributes\":{\"firstname\":\"John\",\"group\":\"test group\",\"role\":\"admin\",\"lastname\":\"Doe\"},\"sign_in_provider\":\"saml.myProvider\",\"tenant\":\"my_tenant_id\"},\"sub\":\"gZG0yELPypZElTmAT9I55prjHg63\"}")
                },
                HttpStatusCode.OK,
                new List<KeyValuePair<string,string>>
                {
                    new("role", "admin"),
                }
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-json-claim=role,gcip,$.firebase.sign_in_attributes.role2",
                new List<Claim>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111"),
                    new("gcip", "{\"auth_time\":1553219869,\"email\":\"demo_user@gmail.com\",\"email_verified\":true,\"firebase\":{\"identities\":{\"email\":[\"demo_user@gmail.com\"],\"saml.myProvider\":[\"demo_user@gmail.com\"]},\"sign_in_attributes\":{\"firstname\":\"John\",\"group\":\"test group\",\"role\":\"admin\",\"lastname\":\"Doe\"},\"sign_in_provider\":\"saml.myProvider\",\"tenant\":\"my_tenant_id\"},\"sub\":\"gZG0yELPypZElTmAT9I55prjHg63\"}")
                },
                HttpStatusCode.OK
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-json-claim=email,gcip,$.firebase.identities.email",
                new List<Claim>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111"),
                    new("gcip", "{\"auth_time\":1553219869,\"email\":\"demo_user@gmail.com\",\"email_verified\":true,\"firebase\":{\"identities\":{\"email\":[\"demo_user@gmail.com\",\"demo_user2@gmail.com\"],\"saml.myProvider\":[\"demo_user@gmail.com\"]},\"sign_in_attributes\":{\"firstname\":\"John\",\"group\":\"test group\",\"role\":\"admin\",\"lastname\":\"Doe\"},\"sign_in_provider\":\"saml.myProvider\",\"tenant\":\"my_tenant_id\"},\"sub\":\"gZG0yELPypZElTmAT9I55prjHg63\"}")
                },
                HttpStatusCode.OK,
                new List<KeyValuePair<string,string>>
                {
                    new("email", "demo_user@gmail.com, demo_user2@gmail.com")
                }
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-json-claim=email,gcip,$.firebase.identities.email",
                new List<Claim>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111"),
                    new("gcip", "{\"auth_time\":1553219869,\"email\":\"demo_user@gmail.com\",\"email_verified\":true,\"firebase\":{\"identities\":{\"email\":[],\"saml.myProvider\":[\"demo_user@gmail.com\"]},\"sign_in_attributes\":{\"firstname\":\"John\",\"group\":\"test group\",\"role\":\"admin\",\"lastname\":\"Doe\"},\"sign_in_provider\":\"saml.myProvider\",\"tenant\":\"my_tenant_id\"},\"sub\":\"gZG0yELPypZElTmAT9I55prjHg63\"}")
                },
                HttpStatusCode.OK
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-json-claim=email,gcip,$.firebase.identities.email",
                new List<Claim>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111"),
                    new("gcip", "{\"auth_time\":1553219869,\"email\":\"demo_user@gmail.com\",\"email_verified\":true,\"firebase\":{\"identities\":{\"email\":null,\"saml.myProvider\":[\"demo_user@gmail.com\"]},\"sign_in_attributes\":{\"firstname\":\"John\",\"group\":\"test group\",\"role\":\"admin\",\"lastname\":\"Doe\"},\"sign_in_provider\":\"saml.myProvider\",\"tenant\":\"my_tenant_id\"},\"sub\":\"gZG0yELPypZElTmAT9I55prjHg63\"}")
                },
                HttpStatusCode.OK
            },
            new object[]
            {
                "?tid=11111111-1111-1111-1111-111111111111&inject-json-claim=email,gcip,$.firebase.identities.email",
                new List<Claim>
                {
                    new("tid", "11111111-1111-1111-1111-111111111111"),
                    new("gcip", "{\"auth_time\":1553219869,\"email\":\"demo_user@gmail.com\",\"email_verified\":true,\"firebase\":{\"identities\":{\"email\":[\"demo_user@gmail.com\",null],\"saml.myProvider\":[\"demo_user@gmail.com\"]},\"sign_in_attributes\":{\"firstname\":\"John\",\"group\":\"test group\",\"role\":\"admin\",\"lastname\":\"Doe\"},\"sign_in_provider\":\"saml.myProvider\",\"tenant\":\"my_tenant_id\"},\"sub\":\"gZG0yELPypZElTmAT9I55prjHg63\"}")
                },
                HttpStatusCode.OK,
                new List<KeyValuePair<string,string>>
                {
                    new("email", "demo_user@gmail.com")
                }
            },
        ];
    }

    [Theory]
    [MemberData(nameof(GetTests))]
    [MemberData(nameof(GetArrayTests))]
    [MemberData(nameof(GetInjectClaimsTests))]
    public async Task Auth(string query, List<Claim> claims, HttpStatusCode status, List<KeyValuePair<string, string>>? expectedHeaders = null)
    {
        var _client = AuthTestsHelpers.GetClient(x => { x.Cookie.Enable = false; });

        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer.GenerateBearerJwtToken(claims));

        var response = await _client.GetAsync($"/auth{query}");
        response.StatusCode.Should().Be(status);

        if (expectedHeaders != null)
        {
            foreach (var expectedHeader in expectedHeaders)
            {
                var found = response.Headers.FirstOrDefault(x => x.Key == expectedHeader.Key);
                found.Should().NotBeNull("Header is missing: " + expectedHeader.Key);

                found.Value.Count().Should().Be(1);
                found.Value.First().Should().Be(expectedHeader.Value);
            }
        }
    }

    [Fact]
    public async Task DisableJWTAuth()
    {
        var _client = AuthTestsHelpers.GetClient(x => x.JWT.Enable = false);

        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer.GenerateBearerJwtToken());

        var response = await _client.GetAsync($"/auth");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task CustomHeader()
    {
        var _client = AuthTestsHelpers.GetClient(x => x.JWT.AuthorizationHeader = "TestHeader");

        _client.DefaultRequestHeaders.TryAddWithoutValidation("TestHeader", FakeJwtIssuer.GenerateBearerJwtToken());

        var response = await _client.GetAsync($"/auth");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    public static IEnumerable<object[]> GetTokenAsQueryParameterTests()
    {
        return
        [
            new object[] // Token Only in Query String
            {
                "",
                new List<Claim>(),
                HttpStatusCode.OK,
                new Dictionary<string, string>()
                {
                    {CustomHeaderNames.XOriginalUrl, $"https://www.example.com?{QueryParameters.AccessToken}={FakeJwtIssuer.GenerateJwtToken(Enumerable.Empty<Claim>())}" }
                }
            },
            new object[] // Bad Token Only in Query String
            {
                "",
                new List<Claim>(),
                HttpStatusCode.Unauthorized,
                new Dictionary<string, string>()
                {
                    {CustomHeaderNames.XOriginalUrl, $"https://www.example.com?{QueryParameters.AccessToken}=BAD" }
                }
            },
            new object[] // Bad Token in Query String and Header, Header is used
            {
                "",
                new List<Claim>(),
                HttpStatusCode.OK,
                new Dictionary<string, string>()
                {
                    {CustomHeaderNames.XOriginalUrl, $"https://www.example.com?{QueryParameters.AccessToken}=BAD" }
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
                    {CustomHeaderNames.XOriginalUrl, "https://www.example.com" }
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
                    {CustomHeaderNames.XOriginalUrl, $"https://www.example.com?{QueryParameters.AccessToken}={FakeJwtIssuer.GenerateJwtToken([new("tid", "11111111-1111-1111-1111-111111111111")])}" }
                },
            },
            new object[] // Token in Query String with Bad Claim
            {
                "?tid=11111111-1111-1111-1111-111111111111",
                new List<Claim>(),
                HttpStatusCode.Unauthorized,
                new Dictionary<string, string>()
                {
                    {CustomHeaderNames.XOriginalUrl, $"https://www.example.com?{QueryParameters.AccessToken}={FakeJwtIssuer.GenerateJwtToken([new("tid", "22222222-2222-2222-2222-222222222222")])}" }
                },
            },

            new object[] // Token Only in Query String
            {
                "",
                new List<Claim>(),
                HttpStatusCode.OK,
                new Dictionary<string, string>()
                {
                    { CustomHeaderNames.XForwardedProto, "https" },
                    { CustomHeaderNames.XForwardedHost, "www.example.com" },
                    { CustomHeaderNames.XForwardedUri, $"?{QueryParameters.AccessToken}={FakeJwtIssuer.GenerateJwtToken(Enumerable.Empty<Claim>())}" }
                }
            },

            new object[] // Missing Headers
            {
                "",
                new List<Claim>(),
                HttpStatusCode.Unauthorized,
                new Dictionary<string, string>()
                {
                }
            },
        ];
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
            new("username", "test")
        };

        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer.GenerateBearerJwtToken(claims));

        var response = await _client.GetAsync("/userinfo");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await response.Content.ReadFromJsonAsync<JsonDocument>();

        json.RootElement.GetProperty("username").GetString().Should().Be("test");
    }

    [Fact]
    public async Task UserInfoMulti()
    {
        var _client = AuthTestsHelpers.GetClient();

        var claims = new List<Claim>()
        {
            new("username", "test"),
            new("multi", "one"),
            new("multi", "two")
        };

        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer.GenerateBearerJwtToken(claims));

        var response = await _client.GetAsync("/userinfo");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await response.Content.ReadFromJsonAsync<JsonDocument>();

        json.RootElement.GetProperty("username").GetString().Should().Be("test");

        json.RootElement.GetProperty("multi").GetArrayLength().Should().Be(2);
        json.RootElement.GetProperty("multi").EnumerateArray().ElementAt(0).GetString().Should().Be("one");
        json.RootElement.GetProperty("multi").EnumerateArray().ElementAt(1).GetString().Should().Be("two");
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
        await SkipAuthNginx(query, Url, httpMethod, status);

        await SkipAuthTraefik(query, Url, httpMethod, status);
    }

    private async Task SkipAuthNginx(string query, string Url, string httpMethod, HttpStatusCode status)
    {
        var _client = AuthTestsHelpers.GetClient();

        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XOriginalUrl, Url);
        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XOriginalMethod, httpMethod);

        var response = await _client.GetAsync($"/auth{query}");
        response.StatusCode.Should().Be(status);
    }

    private async Task SkipAuthTraefik(string query, string Url, string httpMethod, HttpStatusCode status)
    {
        var _client = AuthTestsHelpers.GetClient();

        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XForwardedHost, new Uri(Url).Host);
        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XForwardedMethod, httpMethod);
        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XForwardedProto, new Uri(Url).Scheme);
        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XForwardedUri, "/");

        var response = await _client.GetAsync($"/auth{query}");
        response.StatusCode.Should().Be(status);
    }

    [Fact]
    public async Task SkipAuthMissingHeaders()
    {
        var _client = AuthTestsHelpers.GetClient();

        var response = await _client.GetAsync("/auth?skip-auth=GET,test");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task JWKSAuth()
    {
        var _client = AuthTestsHelpers.GetClient(x =>
        {
            x.Cookie.Enable = false;
            x.JWT.JWKSUrls = ["https://inmemory.microsoft.com/common/discovery/keys2"];
            x.JWT.ValidIssuers = [FakeJwtIssuer2.Issuer];
        });

        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer2.GenerateBearerJwtToken());

        var response = await _client.GetAsync($"/auth");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task JWKSAuthMulti()
    {
        var _client = AuthTestsHelpers.GetClient(x =>
        {
            x.Cookie.Enable = false;
            x.JWT.JWKSUrls = ["https://inmemory.microsoft.com/common/discovery/keys", "https://inmemory.microsoft.com/common/discovery/keys2"];
            x.JWT.ValidIssuers = [FakeJwtIssuer.Issuer, FakeJwtIssuer2.Issuer];
        });

        _client.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse(FakeJwtIssuer.GenerateBearerJwtToken());

        var response = await _client.GetAsync($"/auth");
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        _client.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse(FakeJwtIssuer2.GenerateBearerJwtToken());

        var response2 = await _client.GetAsync($"/auth");
        response2.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task JWKSRetrieverArgs()
    {
        var jwk = new MultiJwksRetriever(["http://tttt"]);
        var results = await jwk.GetConfigurationAsync("http://tttt", new TestServerDocumentRetriever(), CancellationToken.None);
        results.SigningKeys.Count.Should().Be(0);
    }

    [Fact]
    public async Task JWTPrependBearer()
    {
        var _client = AuthTestsHelpers.GetClient(x => x.JWT.PrependBearer = true);

        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer.GenerateJwtToken([]));

        var response = await _client.GetAsync($"/auth");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task RedirectUnauthenticatedSignin()
    {
        var _client = AuthTestsHelpers.GetClient(x => x.Cookie.RedirectUnauthenticatedSignin = true);

        var response = await _client.GetAsync($"/auth");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task RedirectUnauthenticatedSignin2()
    {
        var _client = AuthTestsHelpers.GetClient(x => x.Cookie.RedirectUnauthenticatedSignin = true);

        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer.GenerateBearerJwtToken());

        var response = await _client.GetAsync($"/auth?test=2");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task RedirectUnauthenticatedSignin3()
    {
        var _client = AuthTestsHelpers.GetClient(x => x.Cookie.RedirectUnauthenticatedSignin = true);

        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XOriginalUrl, "https://redirect/test123");
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer.GenerateBearerJwtToken());

        var response = await _client.GetAsync($"/auth?test=2");
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
    }

    [Fact]
    public async Task RedirectUnauthenticatedSigninNginx()
    {
        var _client = AuthTestsHelpers.GetClient(x => x.Cookie.RedirectUnauthenticatedSignin = true);

        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XOriginalUrl, "https://redirect/test123");

        var response = await _client.GetAsync("/auth");
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);

        _client.DefaultRequestHeaders.Clear();
        _client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", response.Headers.GetValues("Set-Cookie"));

        var response2 = await _client.GetAsync(response.Headers.Location);
        response2.StatusCode.Should().Be(HttpStatusCode.Found);
        response2.Headers.Location.Should().Be("https://redirect/test123");
    }

    [Fact]
    public async Task RedirectUnauthenticatedSigninTraefik()
    {
        var _client = AuthTestsHelpers.GetClient(x => x.Cookie.RedirectUnauthenticatedSignin = true);

        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XForwardedProto, "https");
        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XForwardedHost, "redirect");
        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XForwardedUri, "/test123");

        var response = await _client.GetAsync("/auth");
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);

        _client.DefaultRequestHeaders.Clear();
        _client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", response.Headers.GetValues("Set-Cookie"));

        var response2 = await _client.GetAsync(response.Headers.Location);
        response2.StatusCode.Should().Be(HttpStatusCode.Found);
        response2.Headers.Location.Should().Be("https://redirect/test123");
    }

    [Fact]
    public async Task AppendToWWWAuthenticateHeader()
    {
        var _client = AuthTestsHelpers.GetClient(x =>
        {
            x.JWT.AppendToWWWAuthenticateHeader = "test=true";
        });

        var response = await _client.GetAsync("/auth");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        response.Headers.TryGetValues(HeaderNames.WWWAuthenticate, out var values);

        values.First().Should().Be("Bearer test=true, error=\"invalid_token\"");
    }

    [Fact]
    public async Task AddHeadersToUnauthenticated()
    {
        var _client = AuthTestsHelpers.GetClient();

        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XRequestID, "my-request-id");
        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.XOriginalUrl, "https://my-request-url");

        var response = await _client.GetAsync("/auth");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        response.Headers.TryGetValues(CustomHeaderNames.XRequestID, out var values);
        values.First().Should().Be("my-request-id");

        response.Headers.TryGetValues(CustomHeaderNames.XOriginalUrl, out var values2);
        values2.First().Should().Be("https://my-request-url");
    }
}
