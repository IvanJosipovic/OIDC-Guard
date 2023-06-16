using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using oidc_guard;
using System.Dynamic;
using System.Net;
using System.Security.Claims;
using WebMotions.Fake.Authentication.JwtBearer;

namespace oidc_guard_tests;

public class AuthTests : IClassFixture<AuthWebApplicationFactory<Program>>
{
    private readonly AuthWebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public AuthTests(AuthWebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions() { AllowAutoRedirect = true });
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

    [Theory]
    [MemberData(nameof(GetTests))]
    public async Task Auth(string query, List<Claim> claims, HttpStatusCode status)
    {
        dynamic data = new ExpandoObject();

        foreach (var claim in claims)
        {
            ((IDictionary<string, object>)data)[claim.Type] = claim.Value;
        }

        _client.SetFakeBearerToken((object)data);

        var response = await _client.GetAsync($"/auth{query}");
        response.StatusCode.Should().Be(status);
    }

    [Fact]
    public async Task Unauthorized()
    {
        var response = await _client.GetAsync("/auth");
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}

public class AuthWebApplicationFactory<TProgram> : WebApplicationFactory<TProgram> where TProgram : class
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration(config =>
        {
            config.Sources.Clear();

            var inMemoryConfigSettings = new Dictionary<string, string>()
            {
                { "Settings:OpenIdProviderConfigurationUrl", "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" },
            };
            config.AddInMemoryCollection(inMemoryConfigSettings!);
        });

        builder.ConfigureServices((webHost, services) =>
        {
            var settings = services.FirstOrDefault(d => d.ServiceType == typeof(Settings));
            if (settings is not null)
            {
                services.AddSingleton(settings);
            }
            var settingsCfg = webHost.Configuration.GetSection("Settings").Get<Settings>();
            services.AddSingleton(settingsCfg!);
        });

        builder.ConfigureTestServices(services =>
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = FakeJwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = FakeJwtBearerDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = FakeJwtBearerDefaults.AuthenticationScheme;
            }).AddFakeJwtBearer();
        });
    }
}