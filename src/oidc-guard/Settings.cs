namespace oidc_guard;

public class Settings
{
    public bool SkipAuthPreflight { get; set; }
    public LogLevel LogLevel { get; set; }
    public string OpenIdProviderConfigurationUrl { get; set; } = null!;
    public bool RequireHttpsMetadata { get; set; } = true;
    public string? Host { get; set; }
    public string? Scheme { get; set; }
    public CookieAuthSettings Cookie { get; set; } = new();
    public JWTAuthSettings JWT { get; set; } = new();
}

public class CookieAuthSettings
{
    public bool Enable { get; set; } = true;
    public bool SaveTokensInCookie { get; set; }
    public int CookieValidDays { get; set; } = 7;
    public SameSiteMode CookieSameSiteMode { get; set; }
    public string ClientId { get; set; } = null!;
    public string ClientSecret { get; set; } = null!;
    public string CookieName { get; set; } = "oidc-guard";
    public string? CookieDomain { get; set; }
    public string[] Scopes { get; set; } = null!;
    public string[]? AllowedRedirectDomains { get; set; }
}

public class JWTAuthSettings
{
    public string? AuthorizationHeader { get; set; }
    public bool Enable { get; set; } = true;
    public bool EnableAccessTokenInQueryParameter { get; set; }
    public bool ValidateAudience { get; set; }
    public bool ValidateIssuer { get; set; } = true;
    public string[]? ValidAudiences { get; set; }
    public string[]? ValidIssuers { get; set; }
    public string? JWKSUrl { get; set; }
    public bool PrependBearer { get; set; }
}