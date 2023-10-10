using Ductus.FluentDocker.Builders;
using Ductus.FluentDocker.Model.Common;
using k8s;
using KubeUI.Core.Tests;
using Xunit;

namespace oidc_guard_tests.EndToEnd
{
    [CollectionDefinition(EndToEndFixture.FixtureName)]
    public class Collection : ICollectionFixture<EndToEndFixture>
    {
    }

    public class EndToEndFixture : IDisposable
    {
        public const string FixtureName = "EndToEndFixture";

        public string Name { get; set; } = Guid.NewGuid().ToString();

        public string Version { get; set; } = "kindest/node:v1.27.3";

        public Kubernetes Kubernetes { get; set; }

        public EndToEndFixture()
        {
            //// Build oidc-guard image
            //var path = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(GetType().Assembly.Location)))))) + "\\src\\oidc-guard\\";
            //new Builder()
            //  .DefineImage("oidc-guard")
            //  .FromFile(path + "Dockerfile")
            //  .WorkingFolder(new TemplateString(path, true))
            //  .Build()
            //  .Start();

            //// Start OIDC Server
            //new Builder()
            //    .UseContainer()
            //    .UseImage("ghcr.io/soluto/oidc-server-mock:latest")
            //    .WithName("oidc-server-mock")
            //    .ExposePort(9111, 80)
            //    .UseEnvironmentFile("EndToEnd\\settings.env")
            //    .Build()
            //    .Start();

            // Start Kind
            Kind.DownloadClient().Wait();
            Kind.CreateCluster(Name, Version, "EndToEnd/kind-config.yaml").Wait();
            Kubernetes = Kind.GetKubernetesClient(Name).Result;
            Kind.ExportKubeConfig(Name).Wait();

            Helm.DownloadClient().Wait();
            Helm.RepoAdd("nginx", "https://kubernetes.github.io/ingress-nginx").Wait();
            Helm.RepoUpdate().Wait();
            Helm.Upgrade("ingress-nginx", "nginx/ingress-nginx", $"--install -f ./EndToEnd/ingress-nginx-values.yaml --namespace ingress-nginx --create-namespace --kube-context kind-{Name}").Wait();

            //Helm.Install("oidc-guad", "..\\..\\..\\..\\..\\charts\\oidc-guard", "").Wait();

        }

        public void Dispose()
        {
            Kubernetes.Dispose();

            Kind.DeleteCluster(Name).Wait();
        }
    }
}
