using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using oidc_guard;
using System.Text;
using System.Text.Json;

namespace oidc_guard_tests;

internal class MyWebApplicationFactory<TEntryPoint> : WebApplicationFactory<TEntryPoint> where TEntryPoint : class
{
    private readonly Settings settings;

    public MyWebApplicationFactory(Settings settings)
    {
        this.settings = settings;
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.ConfigureHostConfiguration(config =>
        {
            var data = new { Settings = settings };

            config.AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(data))));
        });
        return base.CreateHost(builder);
    }
}
