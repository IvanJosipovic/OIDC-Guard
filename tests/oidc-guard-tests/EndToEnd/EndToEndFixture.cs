using Ductus.FluentDocker.Model.Common;
using Ductus.FluentDocker.Builders;
using k8s;
using k8s.Models;
using KubeUI.Core.Tests;
using Xunit;

namespace oidc_guard_tests.EndToEnd;

[CollectionDefinition(EndToEndFixture.FixtureName)]
public class Collection : ICollectionFixture<EndToEndFixture>
{
}

public class EndToEndFixture : IDisposable
{
    public const string FixtureName = "EndToEndFixture";

    public string Name { get; set; } = Guid.NewGuid().ToString();

    public string Version { get; set; } = "kindest/node:v1.28.0";

    public Kubernetes Kubernetes { get; set; }

    public HttpClient HttpClient { get; set; }

    public EndToEndFixture()
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
            {
                // Return true to ignore SSL certificate errors
                return true;
            }
        };

        HttpClient = new HttpClient(handler);

        // Build oidc-guard image
        var path = Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(GetType().Assembly.Location)))))), "src", "oidc-guard") + Path.DirectorySeparatorChar;
        new Builder()
          .DefineImage("oidc-guard")
          .FromFile(path + "Dockerfile")
          .WorkingFolder(new TemplateString(path, true))
          .Build()
          .Start();

        // Start Kind
        Kind.DownloadClient().Wait();
        Kind.CreateCluster(Name, Version, Path.Combine("EndToEnd", "kind-config.yaml")).Wait();
        Kubernetes = Kind.GetKubernetesClient(Name).Result;

        DeployOIDCServer().Wait();

        DeployDemoApp().Wait();

        Helm.DownloadClient().Wait();
        Helm.RepoAdd("nginx", "https://kubernetes.github.io/ingress-nginx").Wait();
        Helm.RepoUpdate().Wait();
        Helm.Upgrade("ingress-nginx", "nginx/ingress-nginx", $"--install -f {Path.Combine(".", "EndToEnd", "ingress-nginx-values.yaml")} --namespace ingress-nginx --create-namespace --kube-context kind-{Name} --wait").Wait();

        Kind.LoadDockerImage(Name, "oidc-guard:latest").Wait();

        Helm.Upgrade("oidc-guard", Path.Combine("..", "..", "..", "..", "..", "charts", "oidc-guard"), $"--install -f {Path.Combine(".", "EndToEnd", "oidc-guard-values.yaml")} --namespace oidc-guard --create-namespace --kube-context kind-{Name} --wait").Wait();

        while (HttpClient.GetAsync("https://oidc-guard.test.loc:32443/health").Result.StatusCode != System.Net.HttpStatusCode.OK)
        {
            Task.Delay(100).Wait();
        }
    }

    public async Task DeployOIDCServer()
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
                Name = ns.Name(),
                NamespaceProperty = ns.Name()
            },
            Spec = new()
            {
                Replicas = 1,
                Selector = new()
                {
                    MatchLabels = new Dictionary<string, string>
                    {
                        {"app", ns.Name()}
                    }
                },
                Template = new()
                {
                    Metadata = new()
                    {
                        Labels = new Dictionary<string, string>
                        {
                            {"app", ns.Name()}
                        }
                    },
                    Spec = new()
                    {
                        Containers = new List<V1Container>()
                        {
                            new()
                            {
                                Name = ns.Name(),
                                Image = "ghcr.io/soluto/oidc-server-mock:latest",
                                Env = new List<V1EnvVar>()
                                {
                                    new()
                                    {
                                        Name = "API_SCOPES_INLINE",
                                        Value = """[{"Name":"some-app-scope-1"},{"Name":"some-app-scope-2"}]"""
                                    },
                                    new()
                                    {
                                        Name = "API_RESOURCES_INLINE",
                                        Value = """[{"Name":"some-app","Scopes":["some-app-scope-1","some-app-scope-2"]}]"""
                                    },
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
                                        Value = """[{"ClientId":"oidc-guard-mock-client","ClientSecrets":["oidc-guard-mock-client-secret"],"Description":"Client for oidc-guard","AllowedGrantTypes":["authorization_code"],"AllowedScopes":["openid","profile","email"],"RedirectUris":["https://oidc-guard.test.loc:32443/signin-oidc"],},{"ClientId":"client-credentials-mock-client","ClientSecrets":["client-credentials-mock-client-secret"],"Description":"Client for client credentials flow","AllowedGrantTypes":["client_credentials"],"AllowedScopes":["some-app-scope-1"],"ClientClaimsPrefix":"","Claims":[{"Type":"string_claim","Value":"string_claim_value","ValueType":"string"},{"Type":"json_claim","Value":"[\"value1\", \"value2\"]","ValueType":"json"}]}]"""
                                    },
                                    new()
                                    {
                                        Name = "ASPNET_SERVICES_OPTIONS_INLINE",
                                        Value = """{"ForwardedHeadersOptions":{"ForwardedHeaders":"All"}}"""
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
                Name = ns.Name(),
                NamespaceProperty = ns.Name()
            },
            Spec = new()
            {
                Selector = new Dictionary<string, string>
                {
                    {"app", ns.Name()}
                },
                Ports = new List<V1ServicePort>()
                {
                    new()
                    {
                        Port = 32443,
                        TargetPort = 80
                    }
                }
            }
        };

        await Kubernetes.CoreV1.CreateNamespacedServiceAsync(service, service.Namespace());

        var ingress = new V1Ingress()
        {
            Metadata = new()
            {
                Name = ns.Name(),
                NamespaceProperty = ns.Name()
            },
            Spec = new()
            {
                Rules = new List<V1IngressRule>()
                {
                    new()
                    {
                        Host = ns.Name() + "." + ns.Name(),
                        Http = new()
                        {
                            Paths = new List<V1HTTPIngressPath>()
                            {
                                new()
                                {
                                    Path = "/",
                                    PathType = "Prefix",
                                    Backend = new()
                                    {
                                        Service = new()
                                        {
                                            Name = ns.Name(),
                                            Port = new()
                                            {
                                                Number = 32443
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };

        await Kubernetes.NetworkingV1.CreateNamespacedIngressAsync(ingress, ingress.Namespace());
    }

    public async Task DeployDemoApp()
    {
        var ns = new V1Namespace()
        {
            Metadata = new()
            {
                Name = "demo-app"
            }
        };

        await Kubernetes.CreateNamespaceAsync(ns);

        var deployment = new V1Deployment
        {
            Metadata = new()
            {
                Name = ns.Name(),
                NamespaceProperty = ns.Name()
            },
            Spec = new()
            {
                Replicas = 1,
                Selector = new()
                {
                    MatchLabels = new Dictionary<string, string>
                    {
                        {"app", ns.Name()}
                    }
                },
                Template = new()
                {
                    Metadata = new()
                    {
                        Labels = new Dictionary<string, string>
                        {
                            {"app", ns.Name()}
                        }
                    },
                    Spec = new()
                    {
                        Containers = new List<V1Container>()
                        {
                            new()
                            {
                                Name = ns.Name(),
                                Image = "nginx"
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
                Name = ns.Name(),
                NamespaceProperty = ns.Name()
            },
            Spec = new()
            {
                Selector = new Dictionary<string, string>
                {
                    {"app", ns.Name()}
                },
                Ports = new List<V1ServicePort>()
                {
                    new()
                    {
                        Port = 32443,
                        TargetPort = 80
                    }
                }
            }
        };

        await Kubernetes.CoreV1.CreateNamespacedServiceAsync(service, service.Namespace());

        var ingress = new V1Ingress()
        {
            Metadata = new()
            {
                Name = ns.Name(),
                NamespaceProperty = ns.Name(),
                Annotations = new Dictionary<string, string>()
                {
                    { "nginx.ingress.kubernetes.io/auth-url", "http://oidc-guard.oidc-guard.svc.cluster.local:8080/auth" },
                    { "nginx.ingress.kubernetes.io/auth-signin", "https://oidc-guard.test.loc:32443/signin" }
                }
            },
            Spec = new()
            {
                Rules = new List<V1IngressRule>()
                {
                    new()
                    {
                        Host = ns.Name() + ".test.loc",
                        Http = new()
                        {
                            Paths = new List<V1HTTPIngressPath>()
                            {
                                new()
                                {
                                    Path = "/",
                                    PathType = "Prefix",
                                    Backend = new()
                                    {
                                        Service = new()
                                        {
                                            Name = ns.Name(),
                                            Port = new()
                                            {
                                                Number = 32443
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };

        await Kubernetes.NetworkingV1.CreateNamespacedIngressAsync(ingress, ingress.Namespace());
    }

    public void Dispose()
    {
        Kubernetes.Dispose();

        Kind.DeleteCluster(Name).Wait();
    }
}
