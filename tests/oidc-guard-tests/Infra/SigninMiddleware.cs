using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace oidc_guard_tests.Infra;

public class SigninMiddleware : IMiddleware
{
    public async Task InvokeAsync(HttpContext httpContext, RequestDelegate _next)
    {
        if (!HttpMethods.IsGet(httpContext.Request.Method) || !httpContext.Request.Path.StartsWithSegments("/signin-oidc"))
        {
            await _next.Invoke(httpContext);
            return;
        }

        // get and validate query parameters
        // Note: these are absolute minimal, might need to add more depending on your flow logic
        var clientId = httpContext.Request.Query["client_id"].FirstOrDefault();
        var state = httpContext.Request.Query["state"].FirstOrDefault();
        var nonce = httpContext.Request.Query["nonce"].FirstOrDefault();

        if (clientId is null || state is null || nonce is null)
        {
            httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var span = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        var unixTime = span.TotalSeconds;

        var token = FakeJwtIssuer.GenerateJwtToken(new List<Claim>()
        {
            new Claim("nonce", nonce),
            new Claim("iat", unixTime.ToString()),
            new Claim("sub", FakeJwtIssuer.Audience),
            new Claim("tid", "11111111-1111-1111-1111-111111111111"),
            new Claim("gcip", "{\"auth_time\":1553219869,\"email\":\"demo_user@gmail.com\",\"email_verified\":true,\"firebase\":{\"identities\":{\"email\":[\"demo_user@gmail.com\"],\"saml.myProvider\":[\"demo_user@gmail.com\"]},\"sign_in_attributes\":{\"firstname\":\"John\",\"group\":\"test group\",\"role\":\"admin\",\"lastname\":\"Doe\"},\"sign_in_provider\":\"saml.myProvider\",\"tenant\":\"my_tenant_id\"},\"sub\":\"gZG0yELPypZElTmAT9I55prjHg63\"}")
        });

        httpContext.Request.Method = HttpMethods.Post;
        httpContext.Request.QueryString = QueryString.Empty;
        httpContext.Request.ContentType = "application/x-www-form-urlencoded";
        var content = new FormUrlEncodedContent(new Dictionary<string, string>()
        {
            ["id_token"] = token,
            ["token_type"] = "Bearer",
            ["expires_in"] = "3600",
            ["state"] = state,
        });

        using var buffer = new MemoryStream();
        await content.CopyToAsync(buffer, httpContext.RequestAborted);
        buffer.Seek(offset: 0, loc: SeekOrigin.Begin);

        var oldBody = httpContext.Request.Body;
        httpContext.Request.Body = buffer;

        await _next(httpContext);

        httpContext.Request.Body = oldBody;
    }
}
