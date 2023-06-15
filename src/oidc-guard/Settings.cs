﻿namespace OIDC_Guard;

public class Settings
{
    public string CookieDomain { get; set; } = null!;
    public string CookieName { get; set; } = "oidc-guard";
    public string ClientId { get; set; } = null!;
    public string ClientSecret { get; set; } = null!;
    public string OpenIdProviderConfigurationUrl { get; set; } = null!;
    public bool SaveTokensInCookie { get; set; } = true;
}