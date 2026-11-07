using Duende.AspNetCore.Authentication.OAuth2Introspection;
using Microsoft.Extensions.Options;
using Monq.Core.MicroserviceAddressing.Addressing;
using WebApplicationNativeAot.Configuration;

namespace WebApplicationNativeAot.Extensions;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// The authentication service application name used to resolve the introspection endpoint.
    /// </summary>
    const string AuthenticationApplicationName = "pl-identity-service";

    /// <summary>
    /// Configures OAuth2 introspection authentication. The authority is resolved lazily by
    /// application name through the registered <see cref="IMicroserviceAddressProvider"/>.
    /// </summary>
    public static IServiceCollection ConfigureMonqAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        var authConfig = configuration.GetSection("Authentication");

        if (!int.TryParse(authConfig[AuthConstants.AuthenticationConfiguration.CacheDurationSeconds],
                out var cacheDurationSeconds)
            || cacheDurationSeconds <= 0)
            cacheDurationSeconds = 300;

        services.AddAuthentication(OAuth2IntrospectionDefaults.AuthenticationScheme)
            .AddOAuth2Introspection(OAuth2IntrospectionDefaults.AuthenticationScheme, x =>
            {
                x.ClientId = authConfig[AuthConstants.AuthenticationConfiguration.ScopeName];
                x.ClientSecret = authConfig[AuthConstants.AuthenticationConfiguration.ScopeSecret];
                x.CacheDuration = TimeSpan.FromSeconds(cacheDurationSeconds);
                x.NameClaimType = "fullName";
                x.DiscoveryPolicy.RequireHttps = false;
            });

        services.AddOptions<OAuth2IntrospectionOptions>(OAuth2IntrospectionDefaults.AuthenticationScheme)
            .Configure<IServiceProvider>((options, provider) =>
                options.Authority = provider
                    .GetRequiredService<IMicroserviceAddressProvider>()
                    .Resolve(AuthenticationApplicationName, MicroserviceProtocol.Http)
                    .Address
                    .AbsoluteUri);

        return services;
    }
}
