using System.Diagnostics.Metrics;

namespace oidc_guard.Services
{
    public class Instrumentation
    {
        public Counter<long> SignInCounter { get; private set; }
        public Counter<long> SignOutCounter { get; private set; }
        public Counter<long> AuthorizedCounter { get; private set; }
        public Counter<long> UnauthorizedCounter { get; private set; }

        public Instrumentation(IMeterFactory meterFactory)
        {
            const string prefix = "oidc_guard";
            var meter = meterFactory.Create(prefix);

            SignInCounter = meter.CreateCounter<long>(prefix + "_signin", description: "Number of Sign-in operations ongoing.");
            SignOutCounter = meter.CreateCounter<long>(prefix + "_signout", description: "Number of Sign-out operations ongoing.");
            AuthorizedCounter = meter.CreateCounter<long>(prefix + "_authorized", description: "Number of Authorized operations ongoing.");
            UnauthorizedCounter = meter.CreateCounter<long>(prefix + "_unauthorized", description: "Number of Unauthorized operations ongoing.");
        }
    }
}
