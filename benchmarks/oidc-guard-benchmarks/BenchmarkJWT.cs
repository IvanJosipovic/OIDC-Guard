using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using oidc_guard_tests.Infra;
using System.Security.Claims;

namespace oidc_guard_benchmarks;

[MemoryDiagnoser]
public class BenchmarkJWT
{
    private HttpClient client = default!;

    private readonly string query = "/auth";

    [GlobalSetup]
    public void GlobalSetup()
    {
        client = AuthTestsHelpers.GetClient(settings =>
        {
            settings.LogLevel = LogLevel.Error;
        });

        var claims = new List<Claim>()
        {
            new Claim("tid", "11111111-1111-1111-1111-111111111111"),
            new Claim("gcip", "{\"auth_time\":1553219869,\"email\":\"demo_user@gmail.com\",\"email_verified\":true,\"firebase\":{\"identities\":{\"email\":[\"demo_user@gmail.com\"],\"saml.myProvider\":[\"demo_user@gmail.com\"]},\"sign_in_attributes\":{\"firstname\":\"John\",\"group\":\"test group\",\"role\":\"admin\",\"lastname\":\"Doe\"},\"sign_in_provider\":\"saml.myProvider\",\"tenant\":\"my_tenant_id\"},\"sub\":\"gZG0yELPypZElTmAT9I55prjHg63\"}")
        };

        client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer.GenerateBearerJwtToken(claims));
    }

    [Benchmark]
    public async Task Auth()
    {
        await client.GetAsync(query);
    }

    [Benchmark]
    public async Task AuthCheckClaim()
    {
        await client.GetAsync(query + "?tid=11111111-1111-1111-1111-111111111111");
    }

    [Benchmark]
    public async Task InjectClaims()
    {
        await client.GetAsync(query + "?inject-claim=tid");
    }

    [Benchmark]
    public async Task InjectJsonClaims()
    {
        await client.GetAsync(query + "?inject-json-claim=role,gcip,$.firebase.sign_in_attributes.role");
    }
}