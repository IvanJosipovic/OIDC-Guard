using Microsoft.AspNetCore.DataProtection.Repositories;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace oidc_guard.Services;

public class StaticXmlRepository : IXmlRepository
{
    public StaticXmlRepository(string secret)
    {
        KeyGenerator = new Rfc2898DeriveBytes(secret, 0, 1, HashAlgorithmName.SHA256);
    }

    private Rfc2898DeriveBytes KeyGenerator { get; set; }

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
               .Value = Convert.ToBase64String(KeyGenerator.GetBytes(64));

        Keys.Add(element);
    }
}