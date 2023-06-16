using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace oidc_guard_tests;

internal class MyWebApplicationFactory<TEntryPoint> : WebApplicationFactory<TEntryPoint> where TEntryPoint : class
{
    private readonly Dictionary<string, string> inMemoryConfigSettings = new();

    public MyWebApplicationFactory(Dictionary<string, string> inMemoryConfigSettings)
    {
        this.inMemoryConfigSettings = inMemoryConfigSettings;
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.ConfigureHostConfiguration(config =>
        {
            config.AddInMemoryCollection(inMemoryConfigSettings!);
        });
        return base.CreateHost(builder);
    }
}
