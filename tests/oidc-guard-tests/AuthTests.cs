using oidc_guard;
using System.Dynamic;
using System.Net;
using System.Security.Claims;

namespace oidc_guard_tests;

public class AuthTests : IClassFixture<CustomWebApplicationFactory<Program>>
{
    private readonly CustomWebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public AuthTests(CustomWebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
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