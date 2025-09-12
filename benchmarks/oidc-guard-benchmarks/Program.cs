using BenchmarkDotNet.Running;

namespace oidc_guard_benchmarks;

class Program
{
    public static void Main(string[] args)
    {
        BenchmarkRunner.Run<BenchmarkJWT>();
        BenchmarkRunner.Run<BenchmarkCookie>();
    }
}