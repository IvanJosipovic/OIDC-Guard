using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace oidc_guard_tests;

// https://stebet.net/mocking-jwt-tokens-in-asp-net-core-integration-tests/
public static class FakeJwtIssuer
{
    public static string Issuer { get; } = "7bb1f2c9-3e91-45e1-9090-905fee0764cd";
    public static string Audience { get; } = "4529c937-fe72-4c3a-b67c-d282231acf79";

    public static SecurityKey SecurityKey { get; }
    public static SigningCredentials SigningCredentials { get; }

    private static readonly JwtSecurityTokenHandler s_tokenHandler = new JwtSecurityTokenHandler();
    private static readonly RandomNumberGenerator s_rng = RandomNumberGenerator.Create();
    private static readonly byte[] s_key = new byte[32];

    static FakeJwtIssuer()
    {
        s_rng.GetBytes(s_key);
        SecurityKey = new SymmetricSecurityKey(s_key) { KeyId = Guid.NewGuid().ToString() };
        SigningCredentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.HmacSha256);
    }

    public static string GenerateBearerJwtToken(IEnumerable<Claim> claims)
    {
        return "Bearer " + GenerateJwtToken(claims);
    }

    public static string GenerateJwtToken(IEnumerable<Claim> claims)
    {
        return s_tokenHandler.WriteToken(new JwtSecurityToken(Issuer, Audience, claims, DateTime.UtcNow, DateTime.UtcNow.AddMinutes(20), SigningCredentials));
    }
}