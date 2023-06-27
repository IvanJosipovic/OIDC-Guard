using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

namespace oidc_guard_tests;

public class SigninStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return builder =>
        {
            builder.UseMiddleware<SigninMiddleware>();
            next(builder);
        };
    }
}
