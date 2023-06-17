using Microsoft.Extensions.DependencyInjection;
using oidc_guard;
using System.Dynamic;
using System.Net;
using System.Security.Claims;
using WebMotions.Fake.Authentication.JwtBearer;

namespace oidc_guard_tests;

public class AuthTests
{
    static HttpClient GetClient()
    {
        var inMemoryConfigSettings = new Dictionary<string, string?>()
        {
            { "Settings:ClientId", "test" },
            { "Settings:ClientSecret", "secret" },
            { "Settings:OpenIdProviderConfigurationUrl", "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" },
        };

        var factory = new MyWebApplicationFactory<Program>(inMemoryConfigSettings)
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices((webHost, services) =>
                {
                    services.AddAuthentication(options =>
                    {
                        options.DefaultScheme = FakeJwtBearerDefaults.AuthenticationScheme;
                        options.DefaultChallengeScheme = FakeJwtBearerDefaults.AuthenticationScheme;
                        options.DefaultSignInScheme = FakeJwtBearerDefaults.AuthenticationScheme;
                    }).AddFakeJwtBearer();
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
        dynamic data = new ExpandoObject();

        foreach (var claim in claims.GroupBy(x => x.Type))
        {
            ((IDictionary<string, object>)data)[claim.First().Type] = claim.Select(x => x.Value);
        }

        var _client = GetClient();

        _client.SetFakeBearerToken((object)data);

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
}
