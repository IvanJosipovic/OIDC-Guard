using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using oidc_guard;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace oidc_guard_tests.Infra;

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
            var data = new SettingsObject { Settings = settings };

            config.AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(data, typeof(SettingsObject), FactoryJsonSerializerContext.Default))));
        });
        return base.CreateHost(builder);
    }
}

public class SettingsObject
{
    public Settings Settings { get; set; }
}

[JsonSerializable(typeof(SettingsObject))]
internal partial class FactoryJsonSerializerContext : JsonSerializerContext
{
}