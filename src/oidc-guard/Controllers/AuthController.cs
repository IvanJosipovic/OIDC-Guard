using Json.Path;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using System.Diagnostics.Metrics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace oidc_guard.Controllers;

[ApiController]
[Route("")]
[Authorize]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly Settings settings;

    private readonly Counter<long> AuthorizedCounter;

    private readonly Counter<long> UnauthorizedCounter;

    private readonly Counter<long> SigninCounter;

    private readonly Counter<long> SignoutCounter;

    public AuthController(ILogger<AuthController> logger, Settings settings, IMeterFactory meterFactory)
    {
        _logger = logger;
        this.settings = settings;

        var meter = meterFactory.Create("oidc_guard");

        AuthorizedCounter = meter.CreateCounter<long>("oidc_guard_authorized", description: "Number of Authorized operations ongoing.");
        UnauthorizedCounter = meter.CreateCounter<long>("oidc_guard_unauthorized", description: "Number of Unauthorized operations ongoing.");
        SigninCounter = meter.CreateCounter<long>("oidc_guard_signin", description: "Number of Sign-in operations ongoing.");
        SignoutCounter = meter.CreateCounter<long>("oidc_guard_signout", description: "Number of Sign-out operations ongoing.");
    }

    [HttpGet("auth")]
    [AllowAnonymous]
    public IActionResult Auth()
    {
        if (settings.SkipAuthPreflight &&
            HttpContext.Request.Headers[CustomHeaderNames.OriginalMethod][0] == HttpMethod.Options.Method &&
            !StringValues.IsNullOrEmpty(HttpContext.Request.Headers.AccessControlRequestHeaders) &&
            !StringValues.IsNullOrEmpty(HttpContext.Request.Headers.AccessControlRequestMethod) &&
            !StringValues.IsNullOrEmpty(HttpContext.Request.Headers.Origin))
        {
            AuthorizedCounter.Add(1);
            return Ok();
        }

        if (Request.QueryString.HasValue &&
            (Request.Query.TryGetValue(QueryParameters.SkipAuth, out var skipEquals) |
            Request.Query.TryGetValue(QueryParameters.SkipAuthNe, out var skipNotEquals)))
        {
            var originalUrl = HttpContext.Request.Headers[CustomHeaderNames.OriginalUrl][0]!;
            var originalMethod = HttpContext.Request.Headers[CustomHeaderNames.OriginalMethod][0];

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
                            AuthorizedCounter.Add(1);
                            return Ok();
                        }
                    }
                    else
                    {
                        if (Regex.IsMatch(originalUrl, item))
                        {
                            AuthorizedCounter.Add(1);
                            return Ok();
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
                            AuthorizedCounter.Add(1);
                            return Ok();
                        }
                    }
                    else
                    {
                        if (!Regex.IsMatch(originalUrl, item))
                        {
                            AuthorizedCounter.Add(1);
                            return Ok();
                        }
                    }
                }
            }
        }

        if (HttpContext.User.Identity?.IsAuthenticated == false)
        {
            UnauthorizedCounter.Add(1);
            return Unauthorized();
        }

        // Validate based on rules
        if (Request.QueryString.HasValue)
        {
            foreach (var item in Request.Query)
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

                        var claims = HttpContext.User.Claims.Where(x => x.Type == claimName).ToArray();

                        if (claims == null || claims.Length == 0)
                        {
                            continue;
                        }

                        if (claims.Length == 1)
                        {
                            Response.Headers.Append(headerName, claims[0].Value);
                        }
                        else
                        {
                            Response.Headers.Append(headerName, claims.Select(x => x.Value).Aggregate((x, y) => x + ", " + y));
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

                        var jsonClaim = HttpContext.User.Claims.FirstOrDefault(x => x.Type == claimName)?.Value;

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
                            Response.Headers.Append(headerName, ((JsonArray)results.Matches[0].Value!).Where(x => x is not null).Select(x => x!.ToString()).DefaultIfEmpty().Aggregate((x, y) => x + ", " + y));
                        }
                        else
                        {
                            Response.Headers.Append(headerName, results.Matches[0].Value!.ToString());
                        }
                    }
                }
                else if (!HttpContext.User.Claims.Any(x => x.Type == item.Key && item.Value.Contains(x.Value)))
                {
                    UnauthorizedCounter.Add(1);
                    return Unauthorized($"Claim {item.Key} does not match!");
                }
            }
        }

        AuthorizedCounter.Add(1);
        return Ok();
    }

    [HttpGet("signin")]
    [AllowAnonymous]
    public IActionResult SignIn([FromQuery] Uri rd)
    {
        if (!ValidateRedirect(rd))
        {
            return BadRequest();
        }

        SigninCounter.Add(1);

        return Challenge(new AuthenticationProperties { RedirectUri = rd.ToString() });
    }

    [HttpGet("signout")]
    [Authorize]
    public IActionResult SignOut([FromQuery] Uri rd)
    {
        if (!ValidateRedirect(rd))
        {
            return BadRequest();
        }

        SignoutCounter.Add(1);

        return SignOut(new AuthenticationProperties { RedirectUri = rd.ToString() });
    }

    [HttpGet("userinfo")]
    [Authorize]
    public IActionResult UserInfo()
    {
        return Ok(HttpContext.User.Claims.ToDictionary(x => x.Type, x => x.Value));
    }

    [HttpGet("robots.txt")]
    [AllowAnonymous]
    public IActionResult Robots()
    {
        return Ok("User-agent: *\r\nDisallow: /");
    }

    private bool ValidateRedirect(Uri rd)
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