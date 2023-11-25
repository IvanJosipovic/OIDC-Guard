using Json.Path;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Net.Http.Headers;
using oidc_guard.Services;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace oidc_guard;

public partial class Program
{
    public const string AuthenticationScheme = "JWT_OR_COOKIE";

    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateSlimBuilder(args);

        var settings = builder.Configuration.GetSection("Settings").Get<Settings>()!;
        builder.Services.AddSingleton(settings);

        var resource = ResourceBuilder.CreateDefault().AddService(serviceName: "oidc-guard");

        builder.Services
            .AddOpenTelemetry()
            .WithMetrics(metrics =>
            {
                metrics
                    .SetResourceBuilder(resource)
                    .AddRuntimeInstrumentation()
                    .AddAspNetCoreInstrumentation()
                    .AddEventCountersInstrumentation(c =>
                    {
                        c.AddEventSources(
                            "Microsoft.AspNetCore.Hosting",
                            "Microsoft-AspNetCore-Server-Kestrel",
                            "System.Net.Http",
                            "System.Net.Sockets");
                    })
                    .AddView("request-duration", new ExplicitBucketHistogramConfiguration
                    {
                        Boundaries = new double[] { 0, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10 }
                    })
                    .AddMeter(
                        "Microsoft.AspNetCore.Hosting",
                        "Microsoft.AspNetCore.Server.Kestrel",
                        "oidc_guard"
                    )
                    .AddPrometheusExporter();
            });

        builder.Services.AddMetrics();

        builder.Services.AddSingleton<Instrumentation>();

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
                o.RequireHttpsMetadata = settings.RequireHttpsMetadata;
                o.NonceCookie.Name = settings.Cookie.CookieName;
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
                o.RequireHttpsMetadata = settings.RequireHttpsMetadata;

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
            logging.RequestHeaders.Add(CustomHeaderNames.XForwardedHost);
            logging.RequestHeaders.Add(CustomHeaderNames.XForwardedMethod);
            logging.RequestHeaders.Add(CustomHeaderNames.XForwardedProto);
            logging.RequestHeaders.Add(CustomHeaderNames.XForwardedUri);
            logging.RequestHeaders.Add(CustomHeaderNames.XOriginalMethod);
            logging.RequestHeaders.Add(CustomHeaderNames.XOriginalUrl);
            logging.RequestHeaders.Add(HeaderNames.AccessControlRequestHeaders);
            logging.RequestHeaders.Add(HeaderNames.AccessControlRequestMethod);
            logging.RequestHeaders.Add(HeaderNames.Origin);
        });

        builder.Services.AddAuthorization();
        builder.Services.AddHealthChecks();

        builder.Services.Configure<ForwardedHeadersOptions>(options => options.ForwardedHeaders = ForwardedHeaders.All);

        builder.Services.AddHostedService<HostedService>();

        var app = builder.Build();

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
                if (!string.IsNullOrEmpty(settings.JWT.AuthorizationHeader) && context.Request.Headers.TryGetValue(settings.JWT.AuthorizationHeader, out var authHeader))
                {
                    context.Request.Headers.Authorization = authHeader;
                }

                if (settings.JWT.PrependBearer &&
                    context.Request.Headers.ContainsKey(HeaderNames.Authorization) &&
                    !context.Request.Headers.Authorization[0]!.StartsWith(JwtBearerDefaults.AuthenticationScheme + ' '))
                {
                    context.Request.Headers.Authorization = JwtBearerDefaults.AuthenticationScheme + ' ' + context.Request.Headers.Authorization;
                }

                if (settings.JWT.EnableAccessTokenInQueryParameter &&
                    context.Request.Path.StartsWithSegments("/auth") &&
                    context.Request.Headers.TryGetValue(CustomHeaderNames.XOriginalUrl, out var originalUrlHeader) &&
                    Uri.TryCreate(originalUrlHeader, UriKind.RelativeOrAbsolute, out var uri))
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

        app.UseHttpLogging();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapPrometheusScrapingEndpoint();

        app.MapHealthChecks("/health");

        app.MapGet("/robots.txt", () => "User-agent: *\r\nDisallow: /");

        app.MapGet("/userinfo", (HttpContext httpContext) => httpContext.User.Claims.GroupBy(x => x.Type).ToDictionary(x => x.Key, y => y.Count() > 1 ? (object)y.Select(x => x.Value) : y.First().Value))
            .RequireAuthorization();

        app.MapGet("/auth", ([FromServices] Settings settings, [FromServices] Instrumentation meters, HttpContext httpContext) =>
        {
            meters.SignInCounter.Add(1);

            if (settings.SkipAuthPreflight &&
                GetOriginalMethod(httpContext.Request.Headers) == HttpMethod.Options.Method &&
                !StringValues.IsNullOrEmpty(httpContext.Request.Headers.AccessControlRequestHeaders) &&
                !StringValues.IsNullOrEmpty(httpContext.Request.Headers.AccessControlRequestMethod) &&
                !StringValues.IsNullOrEmpty(httpContext.Request.Headers.Origin))
            {
                meters.AuthorizedCounter.Add(1);
                return Results.Ok();
            }

            if (httpContext.Request.QueryString.HasValue &&
                (httpContext.Request.Query.TryGetValue(QueryParameters.SkipAuth, out var skipEquals) |
                httpContext.Request.Query.TryGetValue(QueryParameters.SkipAuthNe, out var skipNotEquals)))
            {
                var originalUrl = GetOriginalUrl(httpContext.Request.Headers);
                var originalMethod = GetOriginalMethod(httpContext.Request.Headers);

                if (skipEquals.Count > 0)
                {
                    foreach (var item in skipEquals)
                    {
                        var commaIndex = item.IndexOf(',');
                        if (commaIndex != -1)
                        {
                            var method = item[..commaIndex];
                            var regex = item[(commaIndex + 1)..];

                            if (method == originalMethod && Regex.IsMatch(originalUrl, regex))
                            {
                                meters.AuthorizedCounter.Add(1);
                                return Results.Ok();
                            }
                        }
                        else
                        {
                            if (Regex.IsMatch(originalUrl, item))
                            {
                                meters.AuthorizedCounter.Add(1);
                                return Results.Ok();
                            }
                        }
                    }
                }

                if (skipNotEquals.Count > 0)
                {
                    foreach (var item in skipNotEquals)
                    {
                        var commaIndex = item.IndexOf(',');
                        if (commaIndex != -1)
                        {
                            var method = item[..commaIndex];
                            var regex = item[(commaIndex + 1)..];

                            if (method != originalMethod && !Regex.IsMatch(originalUrl, regex))
                            {
                                meters.AuthorizedCounter.Add(1);
                                return Results.Ok();
                            }
                        }
                        else
                        {
                            if (!Regex.IsMatch(originalUrl, item))
                            {
                                meters.AuthorizedCounter.Add(1);
                                return Results.Ok();
                            }
                        }
                    }
                }
            }

            if (httpContext.User.Identity?.IsAuthenticated == false)
            {
                meters.UnauthorizedCounter.Add(1);
                return Results.Unauthorized();
            }

            // Validate based on rules
            if (httpContext.Request.QueryString.HasValue)
            {
                foreach (var item in httpContext.Request.Query)
                {
                    if (item.Key.Equals(QueryParameters.SkipAuth, StringComparison.InvariantCultureIgnoreCase))
                    {
                    }
                    else if (item.Key.Equals(QueryParameters.SkipAuthNe, StringComparison.InvariantCultureIgnoreCase))
                    {
                    }
                    else if (item.Key.Equals(QueryParameters.InjectClaim, StringComparison.InvariantCultureIgnoreCase))
                    {
                        foreach (var value in item.Value)
                        {
                            if (string.IsNullOrEmpty(value))
                            {
                                continue;
                            }

                            string claimName;
                            string headerName;

                            if (value.Contains(','))
                            {
                                claimName = value.Split(',')[0];
                                headerName = value.Split(',')[1];
                            }
                            else
                            {
                                claimName = value;
                                headerName = value;
                            }

                            var claims = httpContext.User.Claims.Where(x => x.Type == claimName).ToArray();

                            if (claims == null || claims.Length == 0)
                            {
                                continue;
                            }

                            if (claims.Length == 1)
                            {
                                httpContext.Response.Headers.Append(headerName, claims[0].Value);
                            }
                            else
                            {
                                httpContext.Response.Headers.Append(headerName, claims.Select(x => x.Value).Aggregate((x, y) => x + ", " + y));
                            }
                        }
                    }
                    else if (item.Key.Equals(QueryParameters.InjectJsonClaim, StringComparison.InvariantCultureIgnoreCase))
                    {
                        foreach (var value in item.Value)
                        {
                            if (string.IsNullOrEmpty(value))
                            {
                                continue;
                            }

                            string headerName;
                            string claimName;
                            string jsonPath;

                            headerName = value.Split(',')[0];
                            claimName = value.Split(',')[1];
                            jsonPath = value.Split(',')[2];

                            var jsonClaim = httpContext.User.Claims.FirstOrDefault(x => x.Type == claimName)?.Value;

                            if (jsonClaim is null)
                            {
                                continue;
                            }

                            var results = JsonPath.Parse(jsonPath).Evaluate(JsonNode.Parse(jsonClaim));

                            if (results is null || results.Matches is null || results.Matches.Count == 0 || results.Matches[0].Value is null)
                            {
                                continue;
                            }

                            if (results.Matches[0].Value is JsonArray)
                            {
                                httpContext.Response.Headers.Append(headerName, ((JsonArray)results.Matches[0].Value!).Where(x => x is not null).Select(x => x!.ToString()).DefaultIfEmpty().Aggregate((x, y) => x + ", " + y));
                            }
                            else
                            {
                                httpContext.Response.Headers.Append(headerName, results.Matches[0].Value!.ToString());
                            }
                        }
                    }
                    else if (!httpContext.User.Claims.Any(x => x.Type == item.Key && item.Value.Contains(x.Value)))
                    {
                        meters.UnauthorizedCounter.Add(1);
                        //return Results.Unauthorized($"Claim {item.Key} does not match!");
                        return Results.Unauthorized();
                    }
                }
            }

            meters.AuthorizedCounter.Add(1);
            return Results.Ok();
        });

        app.MapGet("/signin", ([FromServices] Settings settings, [FromServices] Instrumentation meters, [FromQuery] Uri rd) =>
        {
            if (!ValidateRedirect(rd, settings))
            {
                return Results.BadRequest();
            }

            meters.SignInCounter.Add(1);

            return Results.Challenge(new AuthenticationProperties { RedirectUri = rd.ToString() });
        });

        app.MapGet("/signout", ([FromServices] Settings settings, [FromServices] Instrumentation meters, [FromQuery] Uri rd) =>
        {
            if (!ValidateRedirect(rd, settings))
            {
                return Results.BadRequest();
            }

            meters.SignOutCounter.Add(1);

            return Results.SignOut(new AuthenticationProperties { RedirectUri = rd.ToString() });
        })
            .RequireAuthorization();

        app.Run();
    }

    private static string GetOriginalUrl(IHeaderDictionary headers)
    {
        if (headers.TryGetValue(CustomHeaderNames.XOriginalUrl, out var xOriginalUrl))
        {
            return xOriginalUrl!;
        }
        else if (headers.TryGetValue(CustomHeaderNames.XForwardedProto, out var xForwardedProto) &&
            headers.TryGetValue(CustomHeaderNames.XForwardedHost, out var xForwardedHost) &&
            headers.TryGetValue(CustomHeaderNames.XForwardedUri, out var xForwardedUri))
        {
            return $"{xForwardedProto}://{xForwardedHost}{xForwardedUri}";
        }

        throw new Exception("Unable to determine Original Url");
    }

    private static string GetOriginalMethod(IHeaderDictionary headers)
    {
        if (headers.TryGetValue(CustomHeaderNames.XForwardedMethod, out var xForwardedMethod))
        {
            return xForwardedMethod;
        }
        else if (headers.TryGetValue(CustomHeaderNames.XOriginalMethod, out var xOriginalMethod))
        {
            return xOriginalMethod;
        }

        throw new Exception("Unable to determine Original Method");
    }

    private static bool ValidateRedirect(Uri rd, Settings settings)
    {
        if (settings.Cookie.AllowedRedirectDomains?.Length > 0 && rd.IsAbsoluteUri)
        {
            foreach (var allowedDomain in settings.Cookie.AllowedRedirectDomains)
            {
                if ((allowedDomain[0] == '.' && rd.DnsSafeHost.EndsWith(allowedDomain, StringComparison.InvariantCultureIgnoreCase)) ||
                    rd.DnsSafeHost.Equals(allowedDomain, StringComparison.InvariantCultureIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        return true;
    }
}