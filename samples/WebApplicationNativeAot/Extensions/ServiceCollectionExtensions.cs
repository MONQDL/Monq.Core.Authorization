using Duende.AspNetCore.Authentication.OAuth2Introspection;
using WebApplicationNativeAot.Configuration;

namespace WebApplicationNativeAot.Extensions;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Выполнить конфигурацию аутентификации на проекте из провайдера <paramref name="configuration"/>.
    /// </summary>
    public static IServiceCollection ConfigureMonqAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        var authConfig = configuration.GetSection("Authentication");

        services.AddAuthentication(OAuth2IntrospectionDefaults.AuthenticationScheme)
            .AddOAuth2Introspection(OAuth2IntrospectionDefaults.AuthenticationScheme, x =>
            {
                x.Authority = authConfig[AuthConstants.AuthenticationConfiguration.Authority];
                x.ClientId = authConfig[AuthConstants.AuthenticationConfiguration.ScopeName];
                x.ClientSecret = authConfig[AuthConstants.AuthenticationConfiguration.ScopeSecret];
                x.CacheDuration = TimeSpan.FromMinutes(5);
                x.NameClaimType = "fullName";
                x.DiscoveryPolicy.RequireHttps = false;
            });

        return services;
    }
}
