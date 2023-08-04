namespace oidc_guard;

public static class CustomHeaderNames
{
    public static readonly string OriginalMethod = "X-Original-Method";

    public static readonly string OriginalUrl = "X-Original-Url";
}

public static class QueryParameters
{
    public static readonly string AccessToken = "access_token";
    public static readonly string SkipAuth = "skip-auth";
    public static readonly string SkipAuthNe = "skip-auth-ne";
    public static readonly string InjectClaim = "inject-claim";
    public static readonly string InjectJsonClaim = "inject-json-claim";
}