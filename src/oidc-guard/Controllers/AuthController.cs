using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OIDC_Guard.Controllers
{
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
        public async Task<ActionResult> Auth()
        {
            if (HttpContext.User.Identity?.IsAuthenticated == false)
            {
                return Unauthorized();
            }

            // Validate based on rules

            return Ok();
        }

        [HttpGet("signin")]
        [AllowAnonymous]
        public async Task<ActionResult> Signin([FromQuery] string rd)
        {
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = rd
            },
            OpenIdConnectDefaults.AuthenticationScheme);
        }
    }
}