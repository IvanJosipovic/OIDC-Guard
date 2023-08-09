using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Net.Http.Headers;
using oidc_guard.Services;
using Prometheus;

namespace oidc_guard;

public partial class Program
{
    public const string AuthenticationScheme = "JWT_OR_COOKIE";

    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        var settings = builder.Configuration.GetSection("Settings").Get<Settings>()!;
        builder.Services.AddSingleton(settings);

        builder.Logging.AddFilter("Default", settings.LogLevel);
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware", settings.LogLevel);
        builder.Logging.AddFilter("Microsoft.Extensions.Diagnostics.HealthChecks", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.Hosting.Lifetime", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.AspNetCore.DataProtection.KeyManagement.XmlKeyManager", LogLevel.Error);

        var auth = builder.Services.AddAuthentication(o =>
        {
            o.DefaultScheme = AuthenticationScheme;
            o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddPolicyScheme(AuthenticationScheme, AuthenticationScheme, options =>
        {
            options.ForwardDefaultSelector = context =>
            {
                string? authorization = context.Request.Headers.Authorization;

                return settings.JWT.Enable && !string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer ")
                    ? JwtBearerDefaults.AuthenticationScheme
                    : settings.Cookie.Enable
                        ? CookieAuthenticationDefaults.AuthenticationScheme
                        : JwtBearerDefaults.AuthenticationScheme;
            };
        });

        if (settings.Cookie.Enable)
        {
            builder.Services
                .AddDataProtection()
                .AddKeyManagementOptions(x => x.XmlRepository = new StaticXmlRepository(settings.Cookie.ClientSecret));

            auth.AddCookie(o =>
            {
                o.Cookie.Domain = settings.Cookie.CookieDomain;
                o.Cookie.Name = settings.Cookie.CookieName;
                o.ExpireTimeSpan = TimeSpan.FromDays(settings.Cookie.CookieValidDays);
                o.Cookie.MaxAge = TimeSpan.FromDays(settings.Cookie.CookieValidDays);
                o.Cookie.SameSite = settings.Cookie.CookieSameSiteMode;
            })
            .AddOpenIdConnect(o =>
            {
                o.ClientId = settings.Cookie.ClientId;
                o.ClientSecret = settings.Cookie.ClientSecret;
                o.CorrelationCookie.Name = settings.Cookie.CookieName;
                o.MetadataAddress = settings.OpenIdProviderConfigurationUrl;
                o.NonceCookie.Name = settings.Cookie.CookieName;
                o.NonceCookie.SameSite = settings.Cookie.CookieSameSiteMode;
                o.ResponseType = OpenIdConnectResponseType.Code;
                o.SaveTokens = settings.Cookie.SaveTokensInCookie;
                o.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(30);
                o.Scope.Clear();
                foreach (var scope in settings.Cookie.Scopes)
                {
                    o.Scope.Add(scope);
                }
                o.ClaimActions.Clear();
                o.ClaimActions.MapAllExcept("nonce", /*"aud",*/ "azp", "acr", "iss", "iat", "nbf", "exp", "at_hash", "c_hash", "ipaddr", "platf", "ver");
                o.MapInboundClaims = false;
            });
        }

        if (settings.JWT.Enable)
        {
            auth.AddJwtBearer(o =>
            {
                if (!string.IsNullOrEmpty(settings.JWT.JWKSUrl))
                {
                    var httpClient = new HttpClient(o.BackchannelHttpHandler ?? new HttpClientHandler())
                    {
                        Timeout = o.BackchannelTimeout,
                        MaxResponseContentBufferSize = 1024 * 1024 * 10 // 10 MB
                    };

                    o.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                        settings.JWT.JWKSUrl,
                        new JwksRetriever(),
                        new HttpDocumentRetriever(httpClient) { RequireHttps = o.RequireHttpsMetadata }
                    )
                    {
                        RefreshInterval = o.RefreshInterval,
                        AutomaticRefreshInterval = o.AutomaticRefreshInterval
                    };
                }
                else
                {
                    o.MetadataAddress = settings.OpenIdProviderConfigurationUrl;
                }
                o.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(30);
                o.TokenValidationParameters.ValidateAudience = settings.JWT.ValidateAudience;
                o.TokenValidationParameters.ValidAudiences = settings.JWT.ValidAudiences;
                o.TokenValidationParameters.ValidateIssuer = settings.JWT.ValidateIssuer;
                o.TokenValidationParameters.ValidIssuers = settings.JWT.ValidIssuers;
                o.MapInboundClaims = false;
            });
        }

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

            if (settings.JWT.Enable)
            {
                if (!string.IsNullOrEmpty(settings.JWT.AuthorizationHeader) && context.Request.Headers.ContainsKey(settings.JWT.AuthorizationHeader))
                {
                    context.Request.Headers.Authorization = context.Request.Headers[settings.JWT.AuthorizationHeader];
                }

                if (settings.JWT.PrependBearer &&
                    context.Request.Headers.ContainsKey(HeaderNames.Authorization) &&
                    !context.Request.Headers.Authorization[0]!.StartsWith(JwtBearerDefaults.AuthenticationScheme + ' '))
                {
                    context.Request.Headers.Authorization = JwtBearerDefaults.AuthenticationScheme + ' ' + context.Request.Headers.Authorization;
                }

                if (settings.JWT.EnableAccessTokenInQueryParameter &&
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