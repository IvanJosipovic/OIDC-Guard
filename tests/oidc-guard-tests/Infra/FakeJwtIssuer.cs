using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace oidc_guard_tests.Infra;

// https://stebet.net/mocking-jwt-tokens-in-asp-net-core-integration-tests/
public static class FakeJwtIssuer
{
    public static string Issuer { get; } = "7bb1f2c9-3e91-45e1-9090-905fee0764cd";
    public static string Audience { get; } = "4529c937-fe72-4c3a-b67c-d282231acf79";

    public static SecurityKey SecurityKey { get; }
    public static SigningCredentials SigningCredentials { get; }

    public static JsonWebKey JsonWebKey { get; }

    private static readonly JwtSecurityTokenHandler s_tokenHandler = new();

    static FakeJwtIssuer()
    {
        RSA rsa = new RSACryptoServiceProvider(2048);

        var certificateRequest = new CertificateRequest("CN=MyCertificate", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        SecurityKey = new X509SecurityKey(certificate);

        SigningCredentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.RsaSha256Signature);

        JsonWebKey = JsonWebKeyConverter.ConvertFromSecurityKey(SecurityKey);
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

public static class FakeJwtIssuer2
{
    public static string Issuer { get; } = "179e1bd0-b886-49b0-b2ec-55e600429e02";
    public static string Audience { get; } = "386a4651-7206-464d-a8ae-5be813a2fdca";

    public static SecurityKey SecurityKey { get; }
    public static SigningCredentials SigningCredentials { get; }

    public static JsonWebKey JsonWebKey { get; }

    private static readonly JwtSecurityTokenHandler s_tokenHandler = new();

    static FakeJwtIssuer2()
    {
        RSA rsa = new RSACryptoServiceProvider(2048);

        var certificateRequest = new CertificateRequest("CN=MyCertificate", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        SecurityKey = new X509SecurityKey(certificate);

        SigningCredentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.RsaSha256Signature);

        JsonWebKey = JsonWebKeyConverter.ConvertFromSecurityKey(SecurityKey);
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