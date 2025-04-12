namespace oidc_guard;

public static class CustomHeaderNames
{
    public static readonly string XAuthRequestRedirect = "X-Auth-Request-Redirect";
    public static readonly string XForwardedFor = "X-Forwarded-For";
    public static readonly string XForwardedHost = "X-Forwarded-Host";
    public static readonly string XForwardedMethod = "X-Forwarded-Method";
    public static readonly string XForwardedPort = "X-Forwarded-Port";
    public static readonly string XForwardedProto = "X-Forwarded-Proto";
    public static readonly string XForwardedScheme = "X-Forwarded-Scheme";
    public static readonly string XForwardedUri = "X-Forwarded-Uri";
    public static readonly string XOriginalForwardedFor = "X-Original-Forwarded-For";
    public static readonly string XOriginalMethod = "X-Original-Method";
    public static readonly string XOriginalProto = "X-Original-Proto";
    public static readonly string XOriginalUrl = "X-Original-Url";
    public static readonly string XRealIP = "X-Real-IP";
    public static readonly string XRequestID = "X-Request-ID";
    public static readonly string XScheme = "X-Scheme";
    public static readonly string XSentFrom = "X-Sent-From";
}

public static class QueryParameters
{
    public static readonly string AccessToken = "access_token";
    public static readonly string SkipAuth = "skip-auth";
    public static readonly string SkipAuthNe = "skip-auth-ne";
    public static readonly string InjectClaim = "inject-claim";
    public static readonly string InjectJsonClaim = "inject-json-claim";
}