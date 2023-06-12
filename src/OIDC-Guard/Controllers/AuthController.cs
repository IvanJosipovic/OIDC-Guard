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
        [Authorize]
        public async Task<ActionResult> Auth()
        {
            return Ok();
        }

        [HttpGet("signin")]
        [Authorize]
        public async Task<ActionResult> Signin([FromQuery] string? rd)
        {
            return Ok();
        }
    }
}