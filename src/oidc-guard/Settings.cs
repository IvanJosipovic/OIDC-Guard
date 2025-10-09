namespace oidc_guard;

public class Settings
{
    public string Name { get; set; } = "oidc-guard";
    public string Namespace { get; set; } = "default";
    public bool SkipAuthPreflight { get; set; }
    public LogLevel LogLevel { get; set; }
    public LogFormat LogFormat { get; set; }
    public string OpenIdProviderConfigurationUrl { get; set; } = null!;
    public bool RequireHttpsMetadata { get; set; } = true;
    public CookieAuthSettings Cookie { get; set; } = new();
    public JWTAuthSettings JWT { get; set; } = new();
    public string? SslCertSecretName { get; set; }
}

public class CookieAuthSettings
{
    public bool Enable { get; set; } = true;
    public string Host { get; set; } = "";
    public string Scheme { get; set; } = "";
    public string[] AllowedRedirectDomains { get; set; } = [];
    public bool RedirectUnauthenticatedSignin { get; set; }
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string ClientSecretName { get; set; } = "";
    public string ClientSecretKey { get; set; } = "";
    public string? CookieDomain { get; set; } = "test.com";
    public string CookieName { get; set; } = "oidc-guard";
    public SameSiteMode CookieSameSiteMode { get; set; } = SameSiteMode.Unspecified;
    public int CookieValidDays { get; set; } = 7;
    public bool SaveTokensInCookie { get; set; }
    public string[] Scopes { get; set; } = ["openid", "profile"];
}

public class JWTAuthSettings
{
    public bool Enable { get; set; } = true;
    public string[] JWKSUrls { get; set; } = [];
    [Obsolete]
    public string JWKSUrl { get; set; } = "";
    public string AuthorizationHeader { get; set; } = "";
    public bool EnableAccessTokenInQueryParameter { get; set; }
    public bool PrependBearer { get; set; }

    public bool ValidateAudience { get; set; }
    public string[]? ValidAudiences { get; set; } = [];

    public bool ValidateIssuer { get; set; } = true;
    public string[] ValidIssuers { get; set; } = [];
    public string AppendToWWWAuthenticateHeader { get; set; } = "";
}

public enum LogFormat
{
    Simple,
    JSON,

}
