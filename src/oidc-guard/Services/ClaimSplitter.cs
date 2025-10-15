using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace oidc_guard.Services;

public class ClaimSplitter : IClaimsTransformation
{
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var identity = new ClaimsIdentity();

        foreach (var claim in principal.Claims)
        {
            if (claim.Type == "scope" || claim.Type == "groups" || claim.Type == "role")
            {
                if (claim.Value.Contains(' '))
                {
                    var values = claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                    foreach (var value in values)
                    {
                        identity.AddClaim(new Claim(claim.Type, value, claim.ValueType, claim.Issuer));
                    }
                }
            }
        }

        principal.AddIdentity(identity);
        return Task.FromResult(principal);
    }
}
