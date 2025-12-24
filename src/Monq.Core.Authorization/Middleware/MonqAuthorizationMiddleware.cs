using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Monq.Core.Authorization.Extensions;
using Monq.Core.Authorization.Helpers;
using Monq.Core.Authorization.JsonSerializerContexts;
using Monq.Core.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Monq.Core.Authorization.Middleware;

/// <summary>
/// Middleware (промежуточный слой) для обеспечения авторизации действий пользователя.
/// </summary>
public class MonqAuthorizationMiddleware
{
    const string _servicesBaseUri = "BaseUri";

    readonly RequestDelegate _next;
    readonly ILogger<MonqAuthorizationMiddleware> _logger;
    readonly IHttpClientFactory _httpClientFactory;
    readonly HttpMessageHandler? _httpMessageHandler;

    readonly string _userGrantsApiUri;
    readonly TimeSpan _connectionTimeout = TimeSpan.FromSeconds(30);
    readonly MonqAuthorizationOptions _options;
    readonly Stopwatch _sw = new Stopwatch();

    static IEnumerable<string> _forwardedHeaders { get; }
        = new[] { "x-trace-event-id", "x-smon-userspace-id" };

    /// <summary>
    /// Конструктор middleware (промежуточного слоя) для обеспечения авторизации действий пользователя.
    /// Создаёт новый экземпляр <see cref="MonqAuthorizationMiddleware" />.
    /// </summary>
    /// <param name="next">Функция обработки HTTP-запроса.</param>
    /// <param name="configuration">Конфигурация приложения <see cref="IConfiguration" />.</param>
    /// <param name="options">The options.</param>
    /// <param name="logger">Инструментарий логирования <see cref="ILogger" />.</param>
    /// <param name="httpClientFactory">Http Client Factory.</param>
    /// <param name="httpMessageHandler">Обработчик HTTP-запросов.</param>
    public MonqAuthorizationMiddleware(
        RequestDelegate next,
        IConfiguration configuration,
        MonqAuthorizationOptions? options,
        ILogger<MonqAuthorizationMiddleware> logger,
        IHttpClientFactory httpClientFactory,
        HttpMessageHandler? httpMessageHandler = null)
    {
        _httpClientFactory = httpClientFactory;
        _options = options ?? new();
        _next = next;
        _userGrantsApiUri = configuration[_servicesBaseUri] 
            ?? throw new Exception("Can't find 'BaseUri' in IConfiguration providers.");
        _logger = logger;

        _httpMessageHandler = httpMessageHandler;
    }

    /// <summary>
    /// Произвести вызов действий данного middleware в цепочке вызовов.
    /// </summary>
    /// <param name="context">Инкапсуляция данных HTTP-вызова.</param>
    public async Task InvokeAsync(HttpContext context)
    {
        _logger.LogDebug("Start updating user grants.");
        _sw.Reset();
        _sw.Start();
        var isSystemUser = context.User.IsSystemUser();
        if (isSystemUser)
        {
            _sw.Stop();
            _logger.LogDebug("Updating user grants competed at {ElapsedMilliseconds} ms. User is system user. Skip checking.", _sw.ElapsedMilliseconds);
            await _next(context);
            return;
        }

        var subjectId = context.User.Subject();
        if (subjectId == 0)
        {
            _logger.LogDebug("Updating user grants competed at {ElapsedMilliseconds} ms. Claim sub == 0. Skip checking.", _sw.ElapsedMilliseconds);
            await _next(context);
            return;
        }

        await UpdateGrantsAsync(context);
        _logger.LogDebug("Updating user grants competed at {ElapsedMilliseconds} ms.", _sw.ElapsedMilliseconds);
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
