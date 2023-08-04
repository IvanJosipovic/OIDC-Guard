using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Prometheus;
using System.Text.RegularExpressions;

namespace oidc_guard.Controllers;

[ApiController]
[Route("")]
[Authorize]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly Settings settings;

    private static readonly Gauge AuthorizedGauge = Metrics.CreateGauge("oidc_guard_authorized", "Number of Authorized operations ongoing.");

    private static readonly Gauge UnauthorizedGauge = Metrics.CreateGauge("oidc_guard_unauthorized", "Number of Unauthorized operations ongoing.");

    private static readonly Gauge SigninGauge = Metrics.CreateGauge("oidc_guard_signin", "Number of Sign-in operations ongoing.");

    private static readonly Gauge SignoutGauge = Metrics.CreateGauge("oidc_guard_signout", "Number of Sign-out operations ongoing.");

    public AuthController(ILogger<AuthController> logger, Settings settings)
    {
        _logger = logger;
        this.settings = settings;
    }

    [HttpGet("auth")]
    [AllowAnonymous]
    public IActionResult Auth()
    {
        if (settings.SkipAuthPreflight &&
            HttpContext.Request.Headers[CustomHeaderNames.OriginalMethod].FirstOrDefault() == "OPTIONS" &&
            !StringValues.IsNullOrEmpty(HttpContext.Request.Headers.AccessControlRequestHeaders) &&
            !StringValues.IsNullOrEmpty(HttpContext.Request.Headers.AccessControlRequestMethod) &&
            !StringValues.IsNullOrEmpty(HttpContext.Request.Headers.Origin))
        {
            AuthorizedGauge.Inc();
            return Ok();
        }

        if (Request.QueryString.HasValue && (Request.Query.ContainsKey(QueryParameters.SkipAuth) || Request.Query.ContainsKey(QueryParameters.SkipAuthNe)))
        {
            var skipEquals = Request.Query[QueryParameters.SkipAuth];
            var skipNotEquals = Request.Query[QueryParameters.SkipAuthNe];
            var originalUrl = HttpContext.Request.Headers[CustomHeaderNames.OriginalUrl].FirstOrDefault();
            var originalMethod = HttpContext.Request.Headers[CustomHeaderNames.OriginalMethod].FirstOrDefault();

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
                            AuthorizedGauge.Inc();
                            return Ok();
                        }
                    }
                    else
                    {
                        if (Regex.IsMatch(originalUrl, item))
                        {
                            AuthorizedGauge.Inc();
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
                            AuthorizedGauge.Inc();
                            return Ok();
                        }
                    }
                    else
                    {
                        if (!Regex.IsMatch(originalUrl, item))
                        {
                            AuthorizedGauge.Inc();
                            return Ok();
                        }
                    }
                }
            }
        }

        if (HttpContext.User.Identity?.IsAuthenticated == false)
        {
            UnauthorizedGauge.Inc();
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
                            Response.Headers.Add(headerName, claims[0].Value);
                        }
                        else
                        {
                            Response.Headers.Add(headerName, new StringValues(claims.Select(x => x.Value).ToArray()));
                        }
                    }
                }
                else if (!HttpContext.User.Claims.Any(x => x.Type == item.Key && item.Value.Contains(x.Value)))
                {
                    UnauthorizedGauge.Inc();
                    return Unauthorized($"Claim {item.Key} does not match!");
                }
            }
        }

        AuthorizedGauge.Inc();
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

        SigninGauge.Inc();

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

        SignoutGauge.Inc();

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