using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace oidc_guard.Controllers;

[ApiController]
[Route("")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;

    public AuthController(ILogger<AuthController> logger)
    {
        _logger = logger;
    }

    [HttpGet("auth")]
    [AllowAnonymous]
    public ActionResult Auth()
    {
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
                        Response.Headers.Add(headerName, JsonSerializer.Serialize(claims.Select(x => x.Value)));
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
    public ActionResult Signin([FromQuery] string rd)
    {
        return Challenge(new AuthenticationProperties { RedirectUri = rd }, OpenIdConnectDefaults.AuthenticationScheme);
    }
}