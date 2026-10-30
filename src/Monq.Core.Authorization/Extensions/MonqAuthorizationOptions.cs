using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace Monq.Core.Authorization.Extensions;

/// <summary>
/// Options for the user authorization middleware.
/// </summary>
public sealed class MonqAuthorizationOptions
{
    /// <summary>
    /// Gets or sets the absolute base address of the user grants API, hosted by the Work Groups service.
    /// Set by the <c>UseMonqAuthorization</c> overloads after address resolution.
    /// </summary>
    public Uri? UserGrantsApiAddress { get; set; }

    /// <summary>
    /// A delegate called each time an access token is requested.
    /// </summary>
    public Func<HttpContext, Task<string>>? GetAccessToken { get; set; } = HttpContextExtensions.GetToken;

    /// <summary>
    /// A delegate for extracting the userspace identifier from the HTTP context.
    /// </summary>
    public Func<HttpContext, Task<string>>? GetUserspaceId { get; set; } = HttpContextExtensions.GetUserspaceId;

    /// <summary>
    /// If <c>true</c>, the user's permissions list is cached for <see cref="CacheTime"/>.
    /// </summary>
    public bool UseCache { get; set; } = true;

    /// <summary>
    /// The user permissions caching duration when <see cref="UseCache"/> is <c>true</c>. Defaults to 3 seconds.
    /// </summary>
    public TimeSpan CacheTime { get; set; } = TimeSpan.FromSeconds(3);
}
