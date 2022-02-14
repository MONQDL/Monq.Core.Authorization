using IdentityModel.AspNetCore.OAuth2Introspection;
using Monq.Core.Authorization.SampleApi.Configuration;

namespace Monq.Core.Authorization.SampleApi.Extensions
{
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Выполнить конфигурацию аутентификации на проекте из провайдера <paramref name="configuration"/>.
        /// </summary>
        public static IServiceCollection ConfigureSMAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            var authConfig = configuration.GetSection("Authentication");

            services.AddAuthentication(OAuth2IntrospectionDefaults.AuthenticationScheme)
                .AddOAuth2Introspection(OAuth2IntrospectionDefaults.AuthenticationScheme, x =>
                {
                    x.Authority = authConfig[AuthConstants.AuthenticationConfiguration.Authority];
                    x.ClientId = authConfig[AuthConstants.AuthenticationConfiguration.ScopeName];
                    x.ClientSecret = authConfig[AuthConstants.AuthenticationConfiguration.ScopeSecret];
                    x.EnableCaching = true;
                    x.CacheDuration = TimeSpan.FromMinutes(5);
                    x.NameClaimType = "fullName";
                    x.DiscoveryPolicy.RequireHttps = false;
                });

            return services;
        }

        /// <summary>
        /// Выполнить конфигурацию политик авторизации СМ.
        /// </summary>
        /// <param name="hostBuilder">The host builder.</param>
        /// <returns></returns>
        public static IServiceCollection ConfigureAuthorizationPolicies(this IServiceCollection services)
        {
            services.AddAuthorization(options =>
            {
                options.AddPolicy("Authenticated", policy => policy.RequireAuthenticatedUser());
                //options.AddPolicy(AuthConstants.AuthorizationScopes.Read, policyAdmin => policyAdmin.RequireScope("read", "write"));
                //options.AddPolicy(AuthConstants.AuthorizationScopes.Write, policyAdmin => policyAdmin.RequireScope("write"));
                //options.AddPolicy(AuthConstants.AuthorizationScopes.SmonAdmin, policyAdmin => policyAdmin.RequireScope("smon-admin"));
                //options.AddPolicy(AuthConstants.AuthorizationScopes.CloudAdmin, policyAdmin => policyAdmin.RequireScope("cloud-admin"));
            });

            return services;
        }
    }
}
