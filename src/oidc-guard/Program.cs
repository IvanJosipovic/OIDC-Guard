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

        builder.Logging.AddFilter("Default", settings.LogLevel);
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware", settings.LogLevel);
        builder.Logging.AddFilter("Microsoft.Extensions.Diagnostics.HealthChecks", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.Hosting.Lifetime", LogLevel.Warning);

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

        builder.Services.AddHttpLogging(logging =>
        {
            logging.RequestHeaders.Add("x-original-method");
            logging.RequestHeaders.Add("x-original-url");
            logging.RequestHeaders.Add("X-Scheme");
            logging.RequestHeaders.Add("Access-Control-Request-Headers");
            logging.RequestHeaders.Add("Access-Control-Request-Method");
        });

        builder.Services.AddControllers();
        builder.Services.AddSwaggerGen();
        builder.Services.AddHealthChecks();

        builder.Services.Configure<ForwardedHeadersOptions>(options => options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto);

        builder.Services.AddHostedService<HostedService>();

        var app = builder.Build();

        app.UseHttpLogging();

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