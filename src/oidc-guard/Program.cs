using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Net.Http.Headers;
using oidc_guard.Services;
using Prometheus;
using System.IdentityModel.Tokens.Jwt;

namespace oidc_guard;

public partial class Program
{
    public const string AuthenticationScheme = "JWT_OR_COOKIE";

    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        var settings = builder.Configuration.GetSection("Settings").Get<Settings>()!;
        builder.Services.AddSingleton(settings);

        if (builder.Environment.IsProduction())
        {
            builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo("/data-protection"));
        }

        builder.Logging.AddFilter("Default", settings.LogLevel);
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware", settings.LogLevel);
        builder.Logging.AddFilter("Microsoft.Extensions.Diagnostics.HealthChecks", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.Hosting.Lifetime", LogLevel.Warning);

        builder.Services.Configure<CookiePolicyOptions>(o =>
        {
            o.OnAppendCookie = cookieContext => cookieContext.CookieOptions.SameSite = settings.CookieSameSiteMode;
            o.OnDeleteCookie = cookieContext => cookieContext.CookieOptions.SameSite = settings.CookieSameSiteMode;
        });

        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        builder.Services.AddAuthentication(o =>
        {
            o.DefaultScheme = AuthenticationScheme;
            o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
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
            o.CorrelationCookie.Name = settings.CookieName;
            o.MetadataAddress = settings.OpenIdProviderConfigurationUrl;
            o.NonceCookie.Name = settings.CookieName;
            o.ResponseType = OpenIdConnectResponseType.Code;
            o.SaveTokens = settings.SaveTokensInCookie;
            o.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(30);
            o.Scope.Clear();
            foreach (var scope in settings.Scopes)
            {
                o.Scope.Add(scope);
            }
            o.ClaimActions.Clear();
            o.ClaimActions.MapAllExcept("nonce", /*"aud",*/ "azp", "acr", "iss", "iat", "nbf", "exp", "at_hash", "c_hash", "ipaddr", "platf", "ver");
        })
        .AddJwtBearer(o =>
        {
            o.MetadataAddress = settings.OpenIdProviderConfigurationUrl;
            o.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(30);
            o.TokenValidationParameters.ValidateAudience = settings.ValidateAudience;
            o.TokenValidationParameters.ValidAudiences = settings.ValidAudiences;
            o.TokenValidationParameters.ValidateIssuer = settings.ValidateIssuer;
            o.TokenValidationParameters.ValidIssuers = settings.ValidIssuers;
        })
        .AddPolicyScheme(AuthenticationScheme, AuthenticationScheme, options =>
        {
            options.ForwardDefaultSelector = context =>
            {
                string? authorization = context.Request.Headers.Authorization;

                return !string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer ")
                    ? JwtBearerDefaults.AuthenticationScheme
                    : CookieAuthenticationDefaults.AuthenticationScheme;
            };
        });

        builder.Services.AddHttpLogging(logging =>
        {
            logging.RequestHeaders.Add("Access-Control-Request-Headers");
            logging.RequestHeaders.Add("Access-Control-Request-Method");
            logging.RequestHeaders.Add("X-Forwarded-Host");
            logging.RequestHeaders.Add("X-Forwarded-Proto");
            logging.RequestHeaders.Add("X-Forwarded-Scheme");
            logging.RequestHeaders.Add("X-Original-Method");
            logging.RequestHeaders.Add("X-Original-Url");
            logging.RequestHeaders.Add("X-Scheme");
        });

        builder.Services.AddControllers();
        builder.Services.AddHealthChecks();

        builder.Services.Configure<ForwardedHeadersOptions>(options => options.ForwardedHeaders = ForwardedHeaders.All);

        builder.Services.AddHostedService<HostedService>();

        var app = builder.Build();

        app.UseHttpLogging();

        app.UseForwardedHeaders();

        app.Use((context, next) =>
        {
            if (!string.IsNullOrEmpty(settings.Scheme))
            {
                context.Request.Scheme = settings.Scheme;
            }

            if (!string.IsNullOrEmpty(settings.Host))
            {
                context.Request.Host = new HostString(settings.Host);
            }

            if (settings.EnableAccessTokenInQueryParameter &&
                context.Request.Path.StartsWithSegments("/auth") &&
                context.Request.Headers.ContainsKey(CustomHeaderNames.OriginalUrl) &&
                Uri.TryCreate(context.Request.Headers[CustomHeaderNames.OriginalUrl], UriKind.RelativeOrAbsolute, out var uri))
            {
                if (QueryHelpers.ParseQuery(uri.Query).TryGetValue(QueryParameters.AccessToken, out var token) &&
                    !context.Request.Headers.ContainsKey(HeaderNames.Authorization))
                {
                    context.Request.Headers.Authorization = JwtBearerDefaults.AuthenticationScheme + ' ' + token;
                }
            }

            return next();
        });

        app.UseCookiePolicy();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        app.UseMetricServer();

        app.MapHealthChecks("/health");

        app.Run();
    }
}