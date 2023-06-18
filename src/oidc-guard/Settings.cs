﻿namespace oidc_guard;

public class Settings
{
    public bool SaveTokensInCookie { get; set; }
    public bool SkipAuthPreflight { get; set; }
    public bool ValidateAudience { get; set; }
    public bool ValidateIssuer { get; set; } = true;
    public LogLevel LogLevel { get; set; }
    public SameSiteMode CookieSameSiteMode { get; set; }
    public string ClientId { get; set; } = null!;
    public string ClientSecret { get; set; } = null!;
    public string? CookieDomain { get; set; }
    public string CookieName { get; set; } = "oidc-guard";
    public string OpenIdProviderConfigurationUrl { get; set; } = null!;
    public string[]? AllowedRedirectDomains { get; set; }
    public string[]? ValidIssuers { get; set; }
}
