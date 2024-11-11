using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Monq.Core.Authorization.Extensions;
using Monq.Core.Authorization.Middleware;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Расширения для удобства внедрения средствами DI.
/// </summary>
public static class DependencyInjectionExtensions
{
    /// <summary>
    /// Использовать middleware для обеспечения авторизации действий пользователя (см. <see cref="MonqAuthorizationMiddleware"/>).
    /// </summary>
    /// <param name="app">Конвейер конфигурации приложения.</param>
    /// <param name="configuration">Конфигурация приложения <see cref="IConfiguration"/>.</param>
    public static IApplicationBuilder UseMonqAuthorization(this IApplicationBuilder app, IConfiguration configuration)
    {
        var options = CreateDefaultOptions();
        return app.UseMiddleware<MonqAuthorizationMiddleware>(configuration, options);
    }

    /// <summary>
    /// Использовать middleware для обеспечения авторизации действий пользователя (см. <see cref="MonqAuthorizationMiddleware" />).
    /// </summary>
    /// <param name="app">Конвейер конфигурации приложения.</param>
    /// <param name="options">The options.</param>
    /// <param name="configuration">Конфигурация приложения <see cref="IConfiguration" />.</param>
    public static IApplicationBuilder UseMonqAuthorization(
        this IApplicationBuilder app,
        MonqAuthorizationOptions? options,
        IConfiguration configuration)
    {
        options ??= CreateDefaultOptions();
        return app.UseMiddleware<MonqAuthorizationMiddleware>(configuration, options);
    }

    static MonqAuthorizationOptions CreateDefaultOptions() => new MonqAuthorizationOptions
    {
        GetAccessToken = HttpContextExtensions.GetToken,
        GetUserspaceId = HttpContextExtensions.GetUserspaceId
    };
}
