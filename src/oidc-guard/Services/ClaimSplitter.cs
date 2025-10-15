using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace oidc_guard.Services;

public class ClaimSplitter : IClaimsTransformation
{
    private static readonly string[] SplitClaimTypes = ["scope", "groups", "role"];

    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var identities = new List<ClaimsIdentity>();

        foreach (var id in principal.Identities)
        {
            var identity = new ClaimsIdentity(id.AuthenticationType, id.NameClaimType, id.RoleClaimType);

            foreach (var claim in id.Claims)
            {
                if (SplitClaimTypes.Contains(claim.Type) && claim.Value.Contains(' '))
                {
                    var values = claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                    foreach (var value in values)
                    {
                        identity.AddClaim(new Claim(claim.Type, value, claim.ValueType, claim.Issuer));
                    }

                    continue;
                }

                identity.AddClaim(claim);
            }

            identities.Add(identity);
        }

        return Task.FromResult(new ClaimsPrincipal(identities));
    }
}
