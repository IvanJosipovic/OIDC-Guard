using Ductus.FluentDocker.Builders;
using Ductus.FluentDocker.Model.Common;
using k8s;
using k8s.Models;
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
            var path = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(GetType().Assembly.Location)))))) + "\\src\\oidc-guard\\";
            new Builder()
              .DefineImage("oidc-guard")
              .FromFile(path + "Dockerfile")
              .WorkingFolder(new TemplateString(path, true))
              .Build()
              .Start();

            // Start Kind
            Kind.DownloadClient().Wait();
            Kind.CreateCluster(Name, Version, "EndToEnd/kind-config.yaml").Wait();
            Kubernetes = Kind.GetKubernetesClient(Name).Result;

            DeployOIDCServer(Kubernetes).Wait();

            //Helm.DownloadClient().Wait();
            //Helm.RepoAdd("nginx", "https://kubernetes.github.io/ingress-nginx").Wait();
            //Helm.RepoUpdate().Wait();
            //Helm.Upgrade("ingress-nginx", "nginx/ingress-nginx", $"--install -f ./EndToEnd/ingress-nginx-values.yaml --namespace ingress-nginx --create-namespace --kube-context kind-{Name}").Wait();

            Kind.LoadDockerImage(Name, "oidc-guard:latest").Wait();

            Helm.Upgrade("oidc-guad", "..\\..\\..\\..\\..\\charts\\oidc-guard", $"--install -f ./EndToEnd/oidc-guard-values.yaml --namespace oidc-guard --create-namespace --kube-context kind-{Name}").Wait();
        }

        public async Task DeployOIDCServer(Kubernetes kube)
        {
            var ns = new V1Namespace()
            {
                Metadata = new()
                {
                    Name = "oidc-server"
                }
            };

            await Kubernetes.CreateNamespaceAsync(ns);

            var deployment = new V1Deployment
            {
                Metadata = new()
                {
                    Name = "oidc-server",
                    NamespaceProperty = ns.Name()
                },
                Spec = new()
                {
                    Replicas = 1,
                    Selector = new()
                    {
                        MatchLabels = new Dictionary<string, string>
                        {
                            {"app", "oidc-server"}
                        }
                    },
                    Template = new()
                    {
                        Metadata = new()
                        {
                            Labels = new Dictionary<string, string>
                            {
                                {"app", "oidc-server"}
                            }
                        },
                        Spec = new()
                        {
                            Containers = new List<V1Container>()
                            {
                                new()
                                {
                                    Name = "oidc-server",
                                    Image = "ghcr.io/soluto/oidc-server-mock:latest",
                                    Env = new List<V1EnvVar>()
                                    {
                                        new()
                                        {
                                            Name = "SERVER_OPTIONS_INLINE",
                                            Value = """{"AccessTokenJwtType":"JWT","Discovery":{"ShowKeySet":true},"Authentication":{"CookieSameSiteMode":"Lax","CheckSessionCookieSameSiteMode":"Lax"}}"""
                                        },
                                        new()
                                        {
                                            Name = "USERS_CONFIGURATION_INLINE",
                                            Value = """[{"SubjectId":"1","Username":"User1","Password":"pwd","Claims":[{"Type":"name","Value":"Sam_Tailor","ValueType":"string"},{"Type":"email","Value":"sam.tailor@gmail.com","ValueType":"string"},{"Type":"some-api-resource-claim","Value":"Sam's Api Resource Custom Claim","ValueType":"string"},{"Type":"some-api-scope-claim","Value":"Sam's Api Scope Custom Claim","ValueType":"string"},{"Type":"some-identity-resource-claim","Value":"Sam's Identity Resource Custom Claim","ValueType":"string"}]}]"""
                                        },
                                        new()
                                        {
                                            Name = "CLIENTS_CONFIGURATION_INLINE",
                                            Value = """[{"ClientId":"client-credentials-mock-client","ClientSecrets":["client-credentials-mock-client-secret"],"Description":"Client for client credentials flow","AllowedGrantTypes":["code"],"AllowedScopes":["openid","profile","email"],"RedirectUris":["http://localhost:12345/signin-oidc"],"Claims":[{"Type":"string_claim","Value":"string_claim_value","ValueType":"string"},{"Type":"json_claim","Value":"[\"value1\", \"value2\"]","ValueType":"json"}]}]"""
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            };

            await Kubernetes.AppsV1.CreateNamespacedDeploymentAsync(deployment, deployment.Namespace());

            var service = new V1Service()
            {
                Metadata = new()
                {
                    Name = "oidc-server",
                    NamespaceProperty = ns.Name()
                },
                Spec = new()
                {
                    Selector = new Dictionary<string, string>
                    {
                        {"app", "oidc-server"}
                    },
                    Ports = new List<V1ServicePort>()
                    {
                        new() { Port = 80 }
                    }
                }
            };

            await Kubernetes.CoreV1.CreateNamespacedServiceAsync(service, service.Namespace());
        }

        public void Dispose()
        {
            Kubernetes.Dispose();

            Kind.DeleteCluster(Name).Wait();
        }
    }
}
