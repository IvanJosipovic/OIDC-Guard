namespace oidc_guard;

public static class CustomHeaderNames
{
    public static readonly string XOriginalMethod = "X-Original-Method";

    public static readonly string XOriginalUrl = "X-Original-Url";

    public static readonly string XForwardedProto = "X-Forwarded-Proto";

    public static readonly string XForwardedHost = "X-Forwarded-Host";

    public static readonly string XForwardedUri = "X-Forwarded-Uri";

    public static readonly string XForwardedMethod = "X-Forwarded-Method";
}

public static class QueryParameters
{
    public static readonly string AccessToken = "access_token";
    public static readonly string SkipAuth = "skip-auth";
    public static readonly string SkipAuthNe = "skip-auth-ne";
    public static readonly string InjectClaim = "inject-claim";
    public static readonly string InjectJsonClaim = "inject-json-claim";
}