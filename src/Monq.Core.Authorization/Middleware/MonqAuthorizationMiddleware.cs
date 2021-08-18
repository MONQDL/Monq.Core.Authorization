using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Monq.Core.Authorization.Extensions;
using Monq.Core.Authorization.Helpers;
using Monq.Core.Authorization.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Monq.Core.Authorization.Middleware
{
    /// <summary>
    /// Middleware (промежуточный слой) для обеспечения авторизации действий пользователя.
    /// </summary>
    public class MonqAuthorizationMiddleware
    {
        const string _servicesBaseUri = "BaseUri";

        readonly RequestDelegate _next;
        readonly ILogger<MonqAuthorizationMiddleware> _logger;
        readonly HttpMessageHandler? _httpMessageHandler;

        readonly string _userGrantsApiUri;
        readonly TimeSpan _connectionTimeout = TimeSpan.FromSeconds(30);
        readonly MonqAuthorizationOptions? _options;

        static IEnumerable<string> _forwardedHeaders { get; }
            = new[] { "x-trace-event-id", "x-smon-userspace-id" };

        /// <summary>
        /// Конструктор middleware (промежуточного слоя) для обеспечения авторизации действий пользователя.
        /// Создаёт новый экземпляр <see cref="MonqAuthorizationMiddleware" />.
        /// </summary>
        /// <param name="next">Функция обработки HTTP-запроса.</param>
        /// <param name="configuration">Конфигурация приложения <see cref="IConfiguration" />.</param>
        /// <param name="options">The options.</param>
        /// <param name="loggerFactory">Фабрика конфигурирования инструментария логирования <see cref="ILogger" />.</param>
        /// <param name="httpMessageHandler">Обработчик HTTP-запросов.</param>
        public MonqAuthorizationMiddleware(
            RequestDelegate next,
            IConfiguration configuration,
            MonqAuthorizationOptions? options,
            ILoggerFactory loggerFactory,
            HttpMessageHandler? httpMessageHandler = null)
        {
            _options = options;
            _next = next;
            _userGrantsApiUri = configuration[_servicesBaseUri];
            _logger = loggerFactory.CreateLogger<MonqAuthorizationMiddleware>();

            _httpMessageHandler = httpMessageHandler;
        }

        /// <summary>
        /// Конструктор middleware (промежуточного слоя) для обеспечения авторизации действий пользователя.
        /// Создаёт новый экземпляр <see cref="MonqAuthorizationMiddleware" />.
        /// </summary>
        /// <param name="next">Функция обработки HTTP-запроса.</param>
        /// <param name="configuration">Конфигурация приложения <see cref="IConfiguration" />.</param>
        /// <param name="options">The options.</param>
        /// <param name="logger">Инструментарий логирования <see cref="ILogger" />.</param>
        /// <param name="httpMessageHandler">Обработчик HTTP-запросов.</param>
        public MonqAuthorizationMiddleware(
            RequestDelegate next,
            IConfiguration configuration,
            MonqAuthorizationOptions? options,
            ILogger<MonqAuthorizationMiddleware> logger,
            HttpMessageHandler? httpMessageHandler = null)
        {
            _options = options;
            _next = next;
            _userGrantsApiUri = configuration[_servicesBaseUri];
            _logger = logger;

            _httpMessageHandler = httpMessageHandler;
        }

        /// <summary>
        /// Произвести вызов действий данного middleware в цепочке вызовов.
        /// </summary>
        /// <param name="context">Инкапсуляция данных HTTP-вызова.</param>
        public async Task InvokeAsync(HttpContext context)
        {
            var isSystemUser = context.User.IsSystemUser();
            if (isSystemUser)
            {
                await _next(context);
                return;
            }

            var subjectId = context.User.Subject();
            if (subjectId == 0)
            {
                await _next(context);
                return;
            }

            await UpdateGrantsAsync(context);
            await _next(context);
        }

        /// <summary>
        /// Обновить хранилище прав пользователя с сервера авторизации.
        /// </summary>
        /// <param name="context">Инкапсуляция данных HTTP-вызова.</param>
        async Task UpdateGrantsAsync(HttpContext context)
        {
            var userId = context.User.Subject();
            var (userGrants, systemPackets) = await GetUserPacketsAsync(context, userId);
            PacketRepository.Set(userId, userGrants);
            PacketRepository.SetSystemPacketMaps(userId, systemPackets);
        }

        /// <summary>
        /// Получить пакеты прав пользователя.
        /// </summary>
        /// <param name="context">Инкапсуляция данных HTTP-вызова.</param>
        /// <param name="userId">Идентификатор пользователя запроса.</param>
        async Task<(IEnumerable<PacketViewModel>, IEnumerable<SystemPacketMapViewModel>)> GetUserPacketsAsync(HttpContext context, long userId)
        {
            var token = string.Empty;
            if (_options?.GetAccessToken != null)
                token = await _options.GetAccessToken(context);

            var userspaceId = string.Empty;
            if (_options?.GetUserspaceId != null)
                userspaceId = await _options.GetUserspaceId(context);

            using var client = _httpMessageHandler is null ? new HttpClient() : new HttpClient(_httpMessageHandler);

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
            var userGrants = RequestUserPacketsAsync(userId, client);
            var systemPackets = RequestSystemPacketMapsAsync(client);
            await Task.WhenAll(userGrants, systemPackets);
            return (userGrants.Result, systemPackets.Result);
        }

        async Task<IEnumerable<PacketViewModel>> RequestUserPacketsAsync(long userId, HttpClient client)
        {
            try
            {
                var response = await client
                    .GetStringAsync(new Uri(
                        new Uri(_userGrantsApiUri),
                        $"/api/pl/user-grants/users/{userId}/packets"));
                return JsonConvert.DeserializeObject<IEnumerable<PacketViewModel>>(response);
            }
            catch (HttpRequestException e)
            {
                _logger.LogError(new EventId(), e, e.Message, e);
                return Array.Empty<PacketViewModel>();
            }
        }

        async Task<IEnumerable<SystemPacketMapViewModel>> RequestSystemPacketMapsAsync(HttpClient client)
        {
            try
            {
                var response = await client
                    .GetStringAsync(new Uri(
                        new Uri(_userGrantsApiUri),
                        "/api/pl/user-grants/meta/system-packets"));
                return JsonConvert.DeserializeObject<IEnumerable<SystemPacketMapViewModel>>(response);
            }
            catch (HttpRequestException e)
            {
                _logger.LogError(new EventId(), e, e.Message, e);
                return Array.Empty<SystemPacketMapViewModel>();
            }
        }

    }
}
