using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;

namespace oidc_guard.Controllers;

[ApiController]
[Route("")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly Settings settings;

    public AuthController(ILogger<AuthController> logger, Settings settings)
    {
        _logger = logger;
        this.settings = settings;
    }

    [HttpGet("auth")]
    [AllowAnonymous]
    public ActionResult Auth()
    {
        if (settings.SkipAuthPreflight &&
            HttpContext.Request.Headers[CustomHeaderNames.OriginalMethod].FirstOrDefault() == "OPTIONS" &&
            !StringValues.IsNullOrEmpty(HttpContext.Request.Headers.AccessControlRequestHeaders) &&
            !StringValues.IsNullOrEmpty(HttpContext.Request.Headers.AccessControlRequestMethod) &&
            !StringValues.IsNullOrEmpty(HttpContext.Request.Headers.Origin))
        {
            return Ok();
        }

        if (HttpContext.User.Identity?.IsAuthenticated == false)
        {
            return Unauthorized();
        }

        // Validate based on rules

        foreach (var item in Request.Query)
        {
            if (item.Key.Equals("inject-claim", StringComparison.InvariantCultureIgnoreCase))
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

                    var claims = HttpContext.User.Claims.Where(x => x.Type == claimName || x.Properties.Any(y => y.Value == claimName)).ToArray();

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
            else if (!HttpContext.User.Claims.Any(x => (x.Type == item.Key || x.Properties.Any(y => y.Value == item.Key)) && item.Value.Any(y => y?.Equals(x.Value) == true)))
            {
                return Unauthorized();
            }
        }

        return Ok();
    }

    [HttpGet("signin")]
    [AllowAnonymous]
    public ActionResult Signin([FromQuery] Uri rd)
    {
        if (settings.AllowedRedirectDomains?.Length > 0 && rd.IsAbsoluteUri)
        {
            var found = false;
            foreach (var allowedDomain in settings.AllowedRedirectDomains)
            {
                if (allowedDomain[0] == '.' && rd.DnsSafeHost.EndsWith(allowedDomain, StringComparison.InvariantCultureIgnoreCase))
                {
                    found = true;
                    break;
                }
                else if (rd.DnsSafeHost.Equals(allowedDomain, StringComparison.InvariantCultureIgnoreCase))
                {
                    found = true;
                    break;
                }
            }

            if (found == false)
            {
                return BadRequest();
            }
        }

        return Challenge(new AuthenticationProperties { RedirectUri = rd.ToString() });
    }
}