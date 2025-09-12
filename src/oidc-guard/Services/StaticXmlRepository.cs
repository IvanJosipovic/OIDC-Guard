using Microsoft.AspNetCore.DataProtection.Repositories;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace oidc_guard.Services;

public class StaticXmlRepository : IXmlRepository
{
    public StaticXmlRepository(string secret)
    {
        var derivedKey = Rfc2898DeriveBytes.Pbkdf2(
            password: secret,
            salt: Array.Empty<byte>(),
            iterations: 1,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: 64
        );

        KeyBytes = derivedKey;
    }

    private byte[] KeyBytes { get; set; }

    private readonly List<XElement> Keys = [];

    IReadOnlyCollection<XElement> IXmlRepository.GetAllElements()
    {
        return Keys;
    }

    void IXmlRepository.StoreElement(XElement element, string friendlyName)
    {
        element.Attribute("id")!.Value = "0c5444df-6cfb-4e21-a23c-fdcf4787c584";

        element.Element("descriptor")!
               .Element("descriptor")!
               .Element("masterKey")!
               .Element("value")!
               .Value = Convert.ToBase64String(KeyBytes);

        Keys.Add(element);
    }
}