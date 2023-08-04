using Microsoft.AspNetCore.DataProtection.Repositories;
using System.Text;
using System.Xml.Linq;

namespace oidc_guard.Services
{
    public class StaticXmlRepository : IXmlRepository
    {
        public StaticXmlRepository(string secret)
        {
            Secret = secret;
        }

        private string Secret { get; }

        private readonly List<XElement> Keys = new();

        IReadOnlyCollection<XElement> IXmlRepository.GetAllElements()
        {
            return Keys;
        }

        void IXmlRepository.StoreElement(XElement element, string friendlyName)
        {
            var date = new DateTime(2023, 01, 01, 01, 01, 01);
            var expire = new DateTime(2199, 01, 01, 01, 01, 01);

            element.Attribute("id")!.Value = "0c5444df-6cfb-4e21-a23c-fdcf4787c584";

            element.Element("creationDate")!.Value = date.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ");
            element.Element("activationDate")!.Value = date.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ");
            element.Element("expirationDate")!.Value = expire.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ");

            element.Element("descriptor")!
                   .Element("descriptor")!
                   .Element("masterKey")!
                   .Element("value")!
                   .Value = Convert.ToBase64String(Encoding.UTF8.GetBytes(Secret));

            Keys.Add(element);
        }
    }
}
