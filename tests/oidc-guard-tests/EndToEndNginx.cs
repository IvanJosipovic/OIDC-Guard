using oidc_guard_tests.EndToEnd;
using Xunit;

namespace oidc_guard_tests
{
    [Collection(EndToEndFixture.FixtureName)]
    public class EndToEndNginx
    {
        EndToEndFixture fixture;

        public EndToEndNginx(EndToEndFixture fixture)
        {
            this.fixture = fixture;
        }

        [Fact]
        public async Task Test1()
        {

        }
    }
}
