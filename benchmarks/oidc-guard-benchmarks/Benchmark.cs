using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using oidc_guard_tests.Infra;
using System.Security.Claims;

namespace oidc_guard_benchmarks;

[MemoryDiagnoser]
public class Benchmark
{
    private HttpClient client;

    [GlobalSetup]
    public void GlobalSetup()
    {
        client = AuthTestsHelpers.GetClient(settings =>
        {
            settings.LogLevel = LogLevel.Error;
        });

        var claims = new List<Claim>()
        {
            new Claim("tid", "11111111-1111-1111-1111-111111111111")
        };

        client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderNames.Authorization, FakeJwtIssuer.GenerateBearerJwtToken(claims));
    }

    [Benchmark]
    public async Task Auth()
    {
        var response = await client.GetAsync($"/auth");
    }
}