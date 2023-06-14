using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using OIDC_Guard.Services;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.HttpOverrides;

namespace OIDC_Guard
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            //builder.Services.AddSingleton<ISettingsService, SettingsService>();
            //builder.Services.AddSingleton<JwtSecurityTokenHandler>();
            //builder.Services.AddSingleton<IConfigurationRetriever<OpenIdConnectConfiguration>, OpenIdConnectConfigurationRetriever>();
            //builder.Services.AddHostedService<HostedService>();

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(o =>
            {
                o.Cookie.Domain = builder.Configuration.GetValue<string>("CookieDomain");
                o.Cookie.Name = builder.Configuration.GetValue<string>("CookieName");
            })
            .AddOpenIdConnect(o =>
            {
                o.ClientId = builder.Configuration.GetValue<string>("ClientId");
                o.ClientSecret = builder.Configuration.GetValue<string>("ClientSecret");
                o.MetadataAddress = builder.Configuration.GetValue<string>("OpenIdProviderConfigurationUrl");
                o.ResponseType = OpenIdConnectResponseType.Code;
                o.GetClaimsFromUserInfoEndpoint = true;
            });

            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();
            builder.Services.AddHealthChecks();

            builder.Services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            });

            var app = builder.Build();

            app.UseForwardedHeaders();

            app.Use((context, next) =>
            {
                context.Request.Scheme = "https";
                return next();
            });

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.MapHealthChecks("/health");

            app.Run();
        }
    }
}