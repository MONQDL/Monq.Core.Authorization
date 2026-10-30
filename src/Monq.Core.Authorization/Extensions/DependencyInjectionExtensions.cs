using Microsoft.AspNetCore.Builder;
using Monq.Core.Authorization.Extensions;
using Monq.Core.Authorization.Middleware;
using Monq.Core.MicroserviceAddressing.Addressing;
using System;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extensions for convenient DI-based registration.
/// </summary>
public static class DependencyInjectionExtensions
{
    /// <summary>
    /// The Kubernetes application name of the service that hosts the user grants API,
    /// used when no application name is specified explicitly.
    /// </summary>
    public const string DefaultUserGrantsApplicationName = "pl-work-groups-api-service";

    /// <summary>
    /// Adds user authorization middleware using the default user grants application name
    /// (<see cref="DefaultUserGrantsApplicationName"/>) resolved by the registered
    /// <see cref="IMicroserviceAddressProvider"/>.
    /// </summary>
    /// <param name="app">The application pipeline.</param>
    /// <param name="options">Optional user authorization settings.</param>
    public static IApplicationBuilder UseMonqAuthorization(
        this IApplicationBuilder app,
        MonqAuthorizationOptions? options = null)
        => app.UseMonqAuthorization(DefaultUserGrantsApplicationName, options);

    /// <summary>
    /// Adds user authorization middleware using an explicitly resolved user grants API address.
    /// </summary>
    /// <param name="app">The application pipeline.</param>
    /// <param name="userGrantsApiAddress">The absolute base address of the user grants API, hosted by the Work Groups service.</param>
    /// <param name="options">Optional user authorization settings.</param>
    public static IApplicationBuilder UseMonqAuthorization(
        this IApplicationBuilder app,
        Uri userGrantsApiAddress,
        MonqAuthorizationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(userGrantsApiAddress);

        if (!userGrantsApiAddress.IsAbsoluteUri)
            throw new ArgumentException(
                "The user grants API address must be absolute.",
                nameof(userGrantsApiAddress));

        options ??= new MonqAuthorizationOptions();
        options.UserGrantsApiAddress = userGrantsApiAddress;

        return app.UseMiddleware<MonqAuthorizationMiddleware>(options);
    }

    /// <summary>
    /// Adds user authorization middleware using an address resolved by the registered
    /// <see cref="IMicroserviceAddressProvider"/>.
    /// </summary>
    /// <param name="app">The application pipeline.</param>
    /// <param name="applicationName">The Kubernetes application name that hosts the user grants API.</param>
    /// <param name="options">Optional user authorization settings.</param>
    /// <param name="port">An optional non-standard HTTP port.</param>
    /// <param name="addressResolver">An optional resolver override for this integration.</param>
    public static IApplicationBuilder UseMonqAuthorization(
        this IApplicationBuilder app,
        string applicationName,
        MonqAuthorizationOptions? options = null,
        int? port = null,
        IMicroserviceAddressResolver? addressResolver = null)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationName);

        var addressProvider = app.ApplicationServices
            .GetRequiredService<IMicroserviceAddressProvider>();
        var address = addressProvider.Resolve(
            applicationName,
            MicroserviceProtocol.Http,
            port,
            addressResolver).Address;

        return app.UseMonqAuthorization(address, options);
    }
}
