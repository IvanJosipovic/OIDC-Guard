using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using oidc_guard.Services;

namespace oidc_guard;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        var settings = builder.Configuration.GetSection("Settings").Get<Settings>();
        if (settings is not null)
        {
            builder.Services.AddSingleton(settings);
        }

        builder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddCookie(o =>
        {
            o.Cookie.Domain = settings.CookieDomain;
            o.Cookie.Name = settings.CookieName;
        })
        .AddOpenIdConnect(o =>
        {
            o.ClientId = settings.ClientId;
            o.ClientSecret = settings.ClientSecret;
            o.MetadataAddress = settings.OpenIdProviderConfigurationUrl;
            o.ResponseType = OpenIdConnectResponseType.Code;
            o.SaveTokens = settings.SaveTokensInCookie;
        });

        builder.Services.AddControllers();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();
        builder.Services.AddHealthChecks();

        builder.Services.Configure<ForwardedHeadersOptions>(options => options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto);

        builder.Services.AddHostedService<HostedService>();

        var app = builder.Build();

        app.UseForwardedHeaders();

        app.Use((context, next) =>
        {
            context.Request.Scheme = "https";
            return next();
        });

        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        app.MapHealthChecks("/health");

        app.Run();
    }
}