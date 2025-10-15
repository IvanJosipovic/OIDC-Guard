using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace oidc_guard.Services;

public class ScopeSplitter : IClaimsTransformation
{
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var identity = new ClaimsIdentity();

        foreach (var claim in principal.Claims)
        {
            if (claim.Type == "scope")
            {
                if (claim.Value.Contains(' '))
                {
                    var scopes = claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                    foreach (var scope in scopes)
                    {
                        identity.AddClaim(new Claim("scope", scope, claim.ValueType, claim.Issuer));
                    }
                }
                else
                {
                    identity.AddClaim(claim);
                }
            }
        }

        principal.AddIdentity(identity);
        return Task.FromResult(principal);
    }
}
