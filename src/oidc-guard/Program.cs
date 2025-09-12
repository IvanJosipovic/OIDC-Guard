using Json.Path;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Net.Http.Headers;
using oidc_guard.Services;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace oidc_guard;

public class Program
{
    public const string AuthenticationScheme = "JWT_OR_COOKIE";

    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateSlimBuilder(args);

        var settings = builder.Configuration.GetSection("Settings").Get<Settings>()!;
        builder.Services.AddSingleton(settings);

        builder.WebHost.UseKestrelHttpsConfiguration();

        builder.WebHost.ConfigureKestrel((context, serverOptions) =>
        {
            serverOptions.ConfigureHttpsDefaults(listenOptions =>
            {
                listenOptions.ServerCertificate ??= GenerateSelfSignedServerCertificate(settings);
            });
        });

        builder.Services.ConfigureHttpJsonOptions(options =>
        {
            options.SerializerOptions.TypeInfoResolverChain.Add(LocalJsonSerializerContext.Default);
        });

        builder.Services
            .AddOpenTelemetry()
            .WithMetrics(metrics =>
            {
                metrics
                    .SetResourceBuilder(ResourceBuilder.CreateDefault().AddService(serviceName: "oidc-guard"))
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

        if (settings.LogFormat == LogFormat.JSON)
        {
            builder.Logging.AddJsonConsole(options =>
            {
                options.IncludeScopes = false;
                options.TimestampFormat = "HH:mm:ss";
            });
        }

        builder.Logging.AddFilter("Default", settings.LogLevel);
        builder.Logging.AddFilter("Microsoft.AspNetCore", settings.LogLevel);
        builder.Logging.AddFilter("Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware", settings.LogLevel);
        builder.Logging.AddFilter("Microsoft.Extensions.Diagnostics.HealthChecks", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.Hosting.Lifetime", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.AspNetCore.DataProtection", LogLevel.Error);

        var auth = builder.Services.AddAuthentication(o =>
        {
            o.DefaultScheme = AuthenticationScheme;
            o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddPolicyScheme(AuthenticationScheme, AuthenticationScheme, options =>
        {
            options.ForwardDefaultSelector = context =>
            {
                if (settings.Cookie.Enable)
                {
                    string? cookie = context.Request.Headers.Cookie;

                    // If the request contains our cookie, we should prioritize it
                    if (!string.IsNullOrEmpty(cookie) && cookie.Contains(settings.Cookie.CookieName, StringComparison.Ordinal))
                    {
                        return CookieAuthenticationDefaults.AuthenticationScheme;
                    }
                }

                return settings.JWT.Enable ? JwtBearerDefaults.AuthenticationScheme : CookieAuthenticationDefaults.AuthenticationScheme;
            };
        });

        if (settings.Cookie.Enable)
        {
            builder.Services
                .AddDataProtection()
                .AddKeyManagementOptions(x =>
                {
                    x.XmlRepository = new StaticXmlRepository(settings.Cookie.ClientSecret);
                    x.NewKeyLifetime = TimeSpan.FromDays(365);
                });

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

                //todo remove in next major
#pragma warning disable CS0612 // Type or member is obsolete
                var jwksUrls = !string.IsNullOrEmpty(settings.JWT.JWKSUrl) ? [settings.JWT.JWKSUrl] : settings.JWT.JWKSUrls;
#pragma warning restore CS0612 // Type or member is obsolete

                if (jwksUrls != null && jwksUrls.Length != 0)
                {
                    var httpClient = new HttpClient(o.BackchannelHttpHandler ?? new HttpClientHandler())
                    {
                        Timeout = o.BackchannelTimeout,
                        MaxResponseContentBufferSize = 1024 * 1024 * 10 // 10 MB
                    };

                    o.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                        jwksUrls[0],
                        new MultiJwksRetriever(jwksUrls),
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

            if (!string.IsNullOrEmpty(settings.JWT.AppendToWWWAuthenticateHeader))
            {
                builder.Services.Configure<JwtBearerOptions>(x =>
                {
                    // Only add a comma after the first param, if any
                    var spacing = x.Challenge.IndexOf(' ') > 0 ? ", " : " ";

                    x.Challenge = x.Challenge + spacing + settings.JWT.AppendToWWWAuthenticateHeader;
                });
            }
        }

        builder.Services.AddHttpLogging(logging =>
        {
            logging.RequestHeaders.Add(CustomHeaderNames.XAuthRequestRedirect);
            logging.RequestHeaders.Add(CustomHeaderNames.XForwardedFor);
            logging.RequestHeaders.Add(CustomHeaderNames.XForwardedHost);
            logging.RequestHeaders.Add(CustomHeaderNames.XForwardedMethod);
            logging.RequestHeaders.Add(CustomHeaderNames.XForwardedPort);
            logging.RequestHeaders.Add(CustomHeaderNames.XForwardedProto);
            logging.RequestHeaders.Add(CustomHeaderNames.XForwardedScheme);
            logging.RequestHeaders.Add(CustomHeaderNames.XForwardedUri);
            logging.RequestHeaders.Add(CustomHeaderNames.XOriginalForwardedFor);
            logging.RequestHeaders.Add(CustomHeaderNames.XOriginalMethod);
            logging.RequestHeaders.Add(CustomHeaderNames.XOriginalUrl);
            logging.RequestHeaders.Add(CustomHeaderNames.XRealIP);
            logging.RequestHeaders.Add(CustomHeaderNames.XRequestID);
            logging.RequestHeaders.Add(CustomHeaderNames.XScheme);
            logging.RequestHeaders.Add(CustomHeaderNames.XSentFrom);
            logging.RequestHeaders.Add(HeaderNames.Referer);
            logging.RequestHeaders.Add(HeaderNames.Origin);
            logging.RequestHeaders.Add(HeaderNames.AccessControlRequestMethod);
            logging.RequestHeaders.Add(HeaderNames.AccessControlRequestHeaders);

            logging.ResponseHeaders.Add(CustomHeaderNames.XOriginalUrl);
            logging.ResponseHeaders.Add(CustomHeaderNames.XRequestID);
            logging.ResponseHeaders.Add(HeaderNames.WWWAuthenticate);
        });

        builder.Services.AddAuthorization();
        builder.Services.AddHealthChecks();

        builder.Services.Configure<ForwardedHeadersOptions>(options => options.ForwardedHeaders = ForwardedHeaders.All);

        builder.Services.AddHostedService<HostedService>();

        var app = builder.Build();

        app.UseForwardedHeaders();

        app.Use((context, next) =>
        {
            if (!string.IsNullOrEmpty(settings.Cookie.Scheme))
            {
                context.Request.Scheme = settings.Cookie.Scheme;
            }

            if (!string.IsNullOrEmpty(settings.Cookie.Host))
            {
                context.Request.Host = new HostString(settings.Cookie.Host);
            }

            if (settings.JWT.Enable)
            {
                if (!string.IsNullOrEmpty(settings.JWT.AuthorizationHeader) && context.Request.Headers.TryGetValue(settings.JWT.AuthorizationHeader, out var authHeader))
                {
                    context.Request.Headers.Authorization = authHeader;
                }

                if (settings.JWT.PrependBearer &&
                    context.Request.Headers.TryGetValue(HeaderNames.Authorization, out var val) &&
                    !val[0]!.StartsWith(JwtBearerDefaults.AuthenticationScheme + ' '))
                {
                    context.Request.Headers.Authorization = JwtBearerDefaults.AuthenticationScheme + ' ' + context.Request.Headers.Authorization;
                }

                if (settings.JWT.EnableAccessTokenInQueryParameter && context.Request.Path.StartsWithSegments("/auth"))
                {
                    var originalUrl = GetOriginalUrl(context);

                    if (originalUrl != null && Uri.TryCreate(originalUrl, UriKind.RelativeOrAbsolute, out var uri) &&
                        QueryHelpers.ParseQuery(uri.Query).TryGetValue(QueryParameters.AccessToken, out var token) &&
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

        app.MapGet("/auth", ([FromServices] Settings settings, [FromServices] Instrumentation meters, [FromServices] IOptionsMonitor<JwtBearerOptions> options, HttpContext httpContext) =>
        {
            meters.SignInCounter.Add(1);

            if (settings.SkipAuthPreflight &&
                GetOriginalMethod(httpContext.Request.Headers) == HttpMethod.Options.Method &&
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
                var originalUrl = GetOriginalUrl(httpContext);
                var originalMethod = GetOriginalMethod(httpContext.Request.Headers);

                if (originalUrl != null)
                {
                    if (skipEquals.Count > 0)
                    {
                        foreach (var item in skipEquals)
                        {
                            if (item == null)
                            {
                                continue;
                            }

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
                            if (item == null)
                            {
                                continue;
                            }

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
            }

            if (httpContext.User.Identity?.IsAuthenticated == false)
            {
                meters.UnauthorizedCounter.Add(1);

                if (settings.Cookie.RedirectUnauthenticatedSignin)
                {
                    var redirect = GetOriginalUrl(httpContext);

                    if (redirect != null && ValidateRedirect(new Uri(redirect), settings))
                    {
                        meters.SignInCounter.Add(1);

                        return Results.Challenge(new AuthenticationProperties { RedirectUri = redirect });
                    }
                }

                return CustomResults(httpContext, options);
            }

            // Validate based on rules
            if (httpContext.Request.QueryString.HasValue)
            {
                foreach (var item in httpContext.Request.Query)
                {
                    if (item.Key.Equals(QueryParameters.SkipAuth, StringComparison.InvariantCultureIgnoreCase)) { }
                    else if (item.Key.Equals(QueryParameters.SkipAuthNe, StringComparison.InvariantCultureIgnoreCase)) { }
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

                        if (settings.Cookie.RedirectUnauthenticatedSignin)
                        {
                            var redirect = GetOriginalUrl(httpContext);

                            if (redirect != null && ValidateRedirect(new Uri(redirect), settings))
                            {
                                meters.SignInCounter.Add(1);

                                return Results.Challenge(new AuthenticationProperties { RedirectUri = redirect });
                            }
                        }

                        return CustomResults(httpContext, options, "Missing Claim " + item.ToString(), true);
                    }
                }
            }

            meters.AuthorizedCounter.Add(1);
            return Results.Ok();
        });

        app.MapGet("/signin", ([FromServices] Settings settings, [FromServices] Instrumentation meters, [FromQuery] Uri rd, HttpContext httpContext, IOptionsMonitor<JwtBearerOptions> options) =>
        {
            if (!ValidateRedirect(rd, settings))
            {
                return Results.BadRequest();
            }

            meters.SignInCounter.Add(1);


            if (httpContext.User.Identity?.IsAuthenticated == true)
            {
                // If we're here its because a user has failed a auth constraint
                // Return Unauthorized in order to prevent a signin loop
                return CustomResults(httpContext, options, "User missing expected Claims", true);
            }

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

    private static IResult CustomResults(HttpContext context, IOptionsMonitor<JwtBearerOptions> options, string? errorDescription = null, bool forbidden = false)
    {
        // https://tools.ietf.org/html/rfc6750#section-3.1
        // WWW-Authenticate: Bearer error="invalid_token", error_description="The access token expired"
        var builder = new StringBuilder(options.CurrentValue.Challenge);

        if (options.CurrentValue.Challenge.IndexOf(' ') > 0)
        {
            // Only add a comma after the first param, if any
            builder.Append(',');
        }

        builder.Append(" error=\"invalid_token\"");

        if (!string.IsNullOrEmpty(errorDescription))
        {
            builder.Append(", error_description=\"");
            builder.Append(errorDescription);
            builder.Append('\"');
        }

        context.Response.Headers.Append(HeaderNames.WWWAuthenticate, builder.ToString());

        if (context.Request.Headers.TryGetValue(CustomHeaderNames.XRequestID, out var value))
        {
            context.Response.Headers[CustomHeaderNames.XRequestID] = value;
        }

        if (context.Request.Headers.TryGetValue(CustomHeaderNames.XOriginalUrl, out var value2))
        {
            context.Response.Headers[CustomHeaderNames.XOriginalUrl] = value2;
        }

        if (forbidden)
        {
            return Results.Text(content: $$"""
                <!doctype html>
                <html lang="en">
                <head>
                  <meta charset="utf-8" />
                  <title>403 Forbidden</title>
                  <meta name="viewport" content="width=device-width, initial-scale=1" />
                  <style>
                    html, body {
                      height: 100%;
                      margin: 0;
                      font-family: system-ui, sans-serif;
                      background: #f8f9fa;
                      color: #333;
                      display: flex;
                      align-items: center;
                      justify-content: center;
                      text-align: center;
                    }
                    main {
                      max-width: 400px;
                    }
                    h1 {
                      font-size: 3em;
                      margin: 0 0 10px;
                    }
                    p {
                      font-size: 1.1em;
                      margin: 0;
                    }
                  </style>
                </head>
                <body>
                  <main>
                    <h1>403 Forbidden</h1>
                    <p>You are signed in but your account does not have permission to access this resource.</p>
                  </main>
                </body>
                </html>
                """,
                contentType: "text/html",
                statusCode: (int?)HttpStatusCode.Forbidden);
        }

        return Results.Unauthorized();
    }

    private static string? GetOriginalUrl(HttpContext httpContext)
    {
        if (httpContext.Request.Headers.TryGetValue(CustomHeaderNames.XOriginalUrl, out var xOriginalUrl))
        {
            return xOriginalUrl!;
        }
        else if (httpContext.Request.Headers.TryGetValue(HeaderNames.Host, out var host) &&
            httpContext.Request.Headers.TryGetValue(CustomHeaderNames.XForwardedUri, out var xForwardedUri))
        {
            return $"{httpContext.Request.Scheme}://{host}{xForwardedUri}";
        }

        return null;
    }

    private static string? GetOriginalMethod(IHeaderDictionary headers)
    {
        if (headers.TryGetValue(CustomHeaderNames.XForwardedMethod, out var xForwardedMethod))
        {
            return xForwardedMethod;
        }
        else if (headers.TryGetValue(CustomHeaderNames.XOriginalMethod, out var xOriginalMethod))
        {
            return xOriginalMethod;
        }

        return null;
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

    private static X509Certificate2 GenerateSelfSignedServerCertificate(Settings settings)
    {
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddIpAddress(IPAddress.Loopback);
        sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
        sanBuilder.AddDnsName("localhost");

        sanBuilder.AddDnsName($"{settings.Name}.{settings.Namespace}");
        sanBuilder.AddDnsName($"{settings.Name}.{settings.Namespace}.svc");
        sanBuilder.AddDnsName($"{settings.Name}.{settings.Namespace}.svc.cluster.local");

        var distinguishedName = new X500DistinguishedName($"CN={settings.Name}.{settings.Namespace}.svc.cluster.local, O=OIDC-Guard, C=CA");

        using var rsa = RSA.Create(2048);

        var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
        {
            CertificateExtensions = {
                new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false),
                new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2")], false),
                sanBuilder.Build()
            }
        };

        var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddSeconds(-30)), new DateTimeOffset(DateTime.UtcNow.AddYears(10)));

        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null);
    }
}

[JsonSerializable(typeof(Dictionary<string, object>))]
internal partial class LocalJsonSerializerContext : JsonSerializerContext
{
}
