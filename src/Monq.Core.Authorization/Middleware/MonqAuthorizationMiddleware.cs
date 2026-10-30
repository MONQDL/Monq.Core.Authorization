using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Monq.Core.Authorization.Extensions;
using Monq.Core.Authorization.Helpers;
using Monq.Core.Authorization.JsonSerializerContexts;
using Monq.Core.Authorization.Models;
using Monq.Core.Authorization.Telemetry;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;

namespace Monq.Core.Authorization.Middleware;

/// <summary>
/// Middleware for enforcing user action authorization.
/// </summary>
public class MonqAuthorizationMiddleware
{
    readonly RequestDelegate _next;
    readonly ILogger<MonqAuthorizationMiddleware> _logger;
    readonly IHttpClientFactory _httpClientFactory;
    readonly HttpMessageHandler? _httpMessageHandler;

    readonly string _userGrantsApiUri;
    readonly TimeSpan _connectionTimeout = TimeSpan.FromSeconds(30);
    readonly MonqAuthorizationOptions _options;

    static IEnumerable<string> _forwardedHeaders { get; }
        = new[] { "x-trace-event-id", "x-smon-userspace-id" };

    /// <summary>
    /// Initializes a new instance of the <see cref="MonqAuthorizationMiddleware" /> class
    /// for enforcing user action authorization.
    /// </summary>
    /// <param name="next">HTTP request processing function.</param>
    /// <param name="options">The options.</param>
    /// <param name="logger">The logging instrument <see cref="ILogger" />.</param>
    /// <param name="httpClientFactory">Http Client Factory.</param>
    /// <param name="httpMessageHandler">HTTP request handler.</param>
    public MonqAuthorizationMiddleware(
        RequestDelegate next,
        MonqAuthorizationOptions? options,
        ILogger<MonqAuthorizationMiddleware> logger,
        IHttpClientFactory httpClientFactory,
        HttpMessageHandler? httpMessageHandler = null)
    {
        _httpClientFactory = httpClientFactory;
        _options = options ?? new();
        _next = next;
        _userGrantsApiUri = options?.UserGrantsApiAddress?.AbsoluteUri
            ?? throw new ArgumentException(
                "The user grants API address must be set via MonqAuthorizationOptions.UserGrantsApiAddress.",
                nameof(options));
        _logger = logger;

        _httpMessageHandler = httpMessageHandler;
    }

    /// <summary>
    /// Produces the actions of this middleware in the invocation chain.
    /// </summary>
    /// <param name="context">Encapsulation of HTTP call data.</param>
    public async Task InvokeAsync(HttpContext context)
    {
        using (var activity = AuthActivitySource.Source.StartActivity("MonqAuthorization", ActivityKind.Internal))
        {
            _logger.LogDebug("Start updating user grants.");
            var isSystemUser = context.User.IsSystemUser();
            if (isSystemUser)
            {
                activity?.SetTag("auth.skipped", true);
                _logger.LogDebug("Updating user grants completed at {ElapsedMilliseconds} ms. User is system user. Skip checking.",
                    activity?.Duration.TotalMilliseconds);
                await _next(context);
                return;
            }

            var subjectId = context.User.Subject();
            if (subjectId == 0)
            {
                activity?.SetTag("auth.skipped", true);
                _logger.LogDebug("Updating user grants completed at {ElapsedMilliseconds} ms. Claim sub == 0. Skip checking.",
                    activity?.Duration.TotalMilliseconds);
                await _next(context);
                return;
            }

            activity?.SetTag("auth.user.id", subjectId);
            await UpdateGrantsAsync(context);
            _logger.LogDebug("Updating user grants completed at {ElapsedMilliseconds} ms.",
                activity?.Duration.TotalMilliseconds);
        }
        await _next(context);
    }

    /// <summary>
    /// Update the user packets repository from the authorization server.
    /// </summary>
    /// <param name="context">Encapsulation of HTTP call data.</param>
    async ValueTask UpdateGrantsAsync(HttpContext context)
    {
        var userspaceId = string.Empty;
        if (_options.GetUserspaceId != null)
            userspaceId = await _options.GetUserspaceId(context);

        var user = context.User;
        var userId = context.User.Subject();
        var key = user.ObjectKey();
        if (PacketRepository.NotExistsOrExpired(userId, userspaceId, key))
        {
            var userGrants = await GetUserPacketsAsync(context, userId, userspaceId);
            PacketRepository.Set(userId, userspaceId, key, userGrants, _options.UseCache ? _options.CacheTime : null);
        }
    }

    /// <summary>
    /// Get a list of user packets.
    /// </summary>
    /// <param name="context">Encapsulation of HTTP call data.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="userspaceId">Userspace identifier.</param>
    async ValueTask<IEnumerable<PacketViewModel>> GetUserPacketsAsync(HttpContext context, long userId, string userspaceId)
    {
        var client = _httpMessageHandler is not null ? new HttpClient(_httpMessageHandler) : _httpClientFactory.CreateClient();

        var token = string.Empty;
        if (_options.GetAccessToken != null)
            token = await _options.GetAccessToken(context);

        if (!string.IsNullOrEmpty(token))
            client.SetBearerToken(token);
        if (!string.IsNullOrEmpty(userspaceId))
            client.SetUserspaceId(userspaceId);
        client.Timeout = _connectionTimeout;
        foreach (var header in context.Request.Headers)
        {
            if (!_forwardedHeaders.Contains(header.Key.ToLower()) || client.DefaultRequestHeaders.Contains(header.Key))
                continue;

            client.DefaultRequestHeaders.TryAddWithoutValidation(header.Key, header.Value.ToString());
        }
        return await RequestUserPacketsAsync(userId, client);
    }

    async ValueTask<IEnumerable<PacketViewModel>> RequestUserPacketsAsync(long userId, HttpClient client)
    {
        try
        {
            var response = await client
                .GetFromJsonAsync<IEnumerable<PacketViewModel>>(new Uri(
                    new Uri(_userGrantsApiUri),
                    $"/api/pl/user-grants/users/{userId}/packets"),
                    PacketViewModelSerializerContext.Default.IEnumerablePacketViewModel);
            return response ?? Array.Empty<PacketViewModel>();
        }
        catch (HttpRequestException e)
        {
            _logger.LogError(e, e.Message);
            return Array.Empty<PacketViewModel>();
        }
    }
}
