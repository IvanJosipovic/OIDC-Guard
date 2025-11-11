using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using Microsoft.Extensions.Logging;
using oidc_guard_tests.Infra;
using Shouldly;
using System.Net;

namespace oidc_guard_benchmarks;

[JsonExporterAttribute.FullCompressed]
[MemoryDiagnoser]
public class BenchmarkCookie
{
    private HttpClient client = default!;

    private string query = "/auth";

    [GlobalSetup]
    public void GlobalSetup()
    {
        client = AuthTestsHelpers.GetClient(settings =>
        {
            settings.LogLevel = LogLevel.Error;
        });

        var response = client.GetAsync("/signin?rd=/auth").Result;
        response.StatusCode.ShouldBe(HttpStatusCode.Found);
        client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", response.Headers.GetValues("Set-Cookie"));
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
