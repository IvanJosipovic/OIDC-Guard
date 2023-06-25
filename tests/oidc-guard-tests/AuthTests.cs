using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Net.Http.Headers;
using oidc_guard;
using System.Net;
using System.Security.Claims;

namespace oidc_guard_tests;

public class AuthTests
{
    private static HttpClient GetClient(bool SkipAuthPreflight = false, bool EnableAccessTokenInQueryParameter = false)
    {
        IdentityModelEventSource.ShowPII = true;

        var inMemoryConfigSettings = new Dictionary<string, string?>()
        {
            { "Settings:ClientId", "test" },
            { "Settings:ClientSecret", "secret" },
            { "Settings:OpenIdProviderConfigurationUrl", "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" },
            { "Settings:SkipAuthPreflight", SkipAuthPreflight.ToString() },
            { "Settings:EnableAccessTokenInQueryParameter", EnableAccessTokenInQueryParameter.ToString() },
        };

        var factory = new MyWebApplicationFactory<Program>(inMemoryConfigSettings)
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices((webHost, services) =>
                {
                    services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
                    {
                        options.Configuration = new OpenIdConnectConfiguration();
                        options.TokenValidationParameters.IssuerSigningKey = FakeJwtIssuer.SecurityKey;
                        options.TokenValidationParameters.ValidIssuer = FakeJwtIssuer.Issuer;
                        options.TokenValidationParameters.ValidAudience = FakeJwtIssuer.Audience;
                    });

                    services.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
                    {
                        options.Configuration = new OpenIdConnectConfiguration();
                        options.TokenValidationParameters.IssuerSigningKey = FakeJwtIssuer.SecurityKey;
                        options.TokenValidationParameters.ValidIssuer = FakeJwtIssuer.Issuer;
                        options.TokenValidationParameters.ValidAudience = FakeJwtIssuer.Audience;
                    });
                });
            });

        factory.ClientOptions.AllowAutoRedirect = false;

        return factory.CreateDefaultClient();
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
        var _client = GetClient();

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
    public async Task Unauthorized()
    {
        var _client = GetClient();

        var response = await _client.GetAsync("/auth");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task SkipAuthPreflight()
    {
        var _client = GetClient(true);

        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Origin, "localhost");
        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.OriginalMethod, "OPTIONS");
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestHeaders, "origin, x-requested-with");
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestMethod, "DELETE");

        var response = await _client.GetAsync("/auth");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task SkipAuthPreflightDisabled()
    {
        var _client = GetClient(false);

        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.OriginalMethod, "OPTIONS");
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestHeaders, "origin, x-requested-with");
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestMethod, "DELETE");

        var response = await _client.GetAsync("/auth");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task SkipAuthPreflightMissingMethod()
    {
        var _client = GetClient(true);

        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Origin, "localhost");
        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.OriginalMethod, "OPTIONS");
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestHeaders, "origin, x-requested-with");

        var response = await _client.GetAsync("/auth");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task SkipAuthPreflightMissingRequestHeaders()
    {
        var _client = GetClient(true);

        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Origin, "localhost");
        _client.DefaultRequestHeaders.TryAddWithoutValidation(CustomHeaderNames.OriginalMethod, "OPTIONS");
        _client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.AccessControlRequestMethod, "DELETE");

        var response = await _client.GetAsync("/auth");
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
        var _client = GetClient(EnableAccessTokenInQueryParameter: true);

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
}
