using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using oidc_guard.Services;
using Microsoft.AspNetCore.DataProtection;

namespace oidc_guard;

public partial class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        var settings = builder.Configuration.GetSection("Settings").Get<Settings>()!;
        builder.Services.AddSingleton(settings);

        if (builder.Environment.IsProduction())
        {
            builder.Services.AddDataProtection()
                .PersistKeysToFileSystem(new DirectoryInfo("/data-protection"));
        }

        builder.Services.Configure<CookiePolicyOptions>(options =>
        {
            options.OnAppendCookie = cookieContext => cookieContext.CookieOptions.SameSite = settings.CookieSameSiteMode;
            options.OnDeleteCookie = cookieContext => cookieContext.CookieOptions.SameSite = settings.CookieSameSiteMode;
        });

        var auth = builder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddCookie(o =>
        {
            o.Cookie.Domain = settings?.CookieDomain;
            o.Cookie.Name = settings?.CookieName;
        })
        .AddOpenIdConnect(o =>
        {
            o.ClientId = settings?.ClientId;
            o.ClientSecret = settings?.ClientSecret;
            o.MetadataAddress = settings?.OpenIdProviderConfigurationUrl;
            o.ResponseType = OpenIdConnectResponseType.Code;
            o.SaveTokens = (settings?.SaveTokensInCookie) ?? false;
        });

        builder.Services.AddControllers();
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

        app.UseCookiePolicy();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        app.MapHealthChecks("/health");

        app.Run();
    }
}