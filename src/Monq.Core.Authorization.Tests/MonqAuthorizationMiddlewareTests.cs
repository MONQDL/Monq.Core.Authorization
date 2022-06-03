using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Monq.Core.Authorization.Middleware;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace Monq.Core.Authorization.Tests
{
#pragma warning disable IDE0021 // Use expression body for constructors
    [Collection("Serial")]
    public class MonqAuthorizationMiddlewareTests
    {
        readonly IConfiguration _config;
        readonly Uri _uri = new Uri("http://localhost:5005");

        static readonly JsonSerializerOptions _jsonSerializationOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DictionaryKeyPolicy = JsonNamingPolicy.CamelCase
        };

        public MonqAuthorizationMiddlewareTests()
        {
            _config = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string> { { "BaseUri", _uri.ToString() } })
                .Build();
        }

        [Theory(DisplayName = "MonqAuthorizationMiddleware: Проверка корректной последовательности работы middleware.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public async Task ShouldProperlyInvokeMiddleware(int seed)
        {
            var sporadic = new Random(seed);
            const string responseBody = "test response body";
            var userId = sporadic.GetId();
            var eventId = sporadic.Next();
            var httpClientFactoryMock = new Mock<IHttpClientFactory>();
            httpClientFactoryMock
                .Setup(x => x.CreateClient(It.IsAny<string>()))
                .Returns(new HttpClient());

            var logger = new Mock<ILogger<MonqAuthorizationMiddleware>>();
            var middleware = new MonqAuthorizationMiddleware(
                async (innerHttpContext) =>
                {
                    // Эмулируем вызовы по конвейеру и логирование результата
                    await innerHttpContext.Response.WriteAsync(responseBody);
                    logger.Object.Log(LogLevel.Information, eventId, responseBody, null, (state, _) => state);
                },
                _config,
                null,
                logger.Object,
                httpClientFactoryMock.Object);

            var userPrincipal = TestData.CreateUserClaimPrincipal(userId);
            await middleware.InvokeAsync(new DefaultHttpContext { User = userPrincipal });

            // В этом тесте не используется FakeResponseHandler, поэтому запрос к серверу авторизации
            // приведёт к логированию ошибки. Наличие ошибки говорит о том, что алгоритм отработал.
            // TODO: Исправить.
            //logger.Verify(val => val.Log(
            //    LogLevel.Error,
            //    It.IsAny<EventId>(),
            //    It.IsAny<object>(),
            //    It.IsAny<Exception>(),
            //    It.IsAny<Func<object, Exception, string>>()));

            // В этом тесте проверяем, успешно ли завершена основная ветка алгоритма. В случае, если это
            // так, будет вызван request delegate, который приведёт к логированию псевдоответа.
            logger.Verify(val => val.Log(
                LogLevel.Information,
                eventId,
                It.Is<string>(entry => entry == responseBody),
                null,
                It.IsAny<Func<string, Exception, string>>()));
        }

        [Theory(DisplayName = "MonqAuthorizationMiddleware: Проверка корректного заполнения пользовательских прав.", Skip = "Random failers.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public async Task ShouldProperlyGetUserGrants(int seed)
        {
            var sporadic = new Random(seed);
            const string responseBody = "test response body";
            var userId = sporadic.GetId();
            var eventId = sporadic.Next();
            var workGroupId = sporadic.GetId();
            var packetId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var fakeResponseHandler = new FakeResponseHandler();
            var logger = new Mock<ILogger<MonqAuthorizationMiddleware>>();
            var middleware = new MonqAuthorizationMiddleware(
                async (innerHttpContext) =>
                {
                    // Эмулируем вызовы по конвейеру и логирование результата
                    await innerHttpContext.Response.WriteAsync(responseBody);
                    logger.Object.Log(LogLevel.Information, eventId, responseBody, null, (state, _) => state);
                },
                _config,
                null,
                logger.Object,
                new Mock<IHttpClientFactory>().Object,
                fakeResponseHandler);

            var packetToSet = TestData.CreatePacket(packetId, userspaceId, workGroupId, userId);
            var packetsToSet = new[] { packetToSet };

            fakeResponseHandler.AddFakeResponse(new Uri(_uri, $"/api/pl/user-grants/users/{userId}/packets"),
                new HttpResponseMessage(HttpStatusCode.OK),
                JsonSerializer.Serialize(packetsToSet, _jsonSerializationOptions));

            var userPrincipal = TestData.CreateUserClaimPrincipal(userId);
            await middleware.InvokeAsync(new DefaultHttpContext { User = userPrincipal });

            // Чтобы убедиться, что _иных_ проблем не возникло, проверяем, завершилась ли цепочка исполнения
            logger.Verify(val => val.Log(
                LogLevel.Information,
                eventId,
                It.Is<string>(entry => entry == responseBody),
                null,
                It.IsAny<Func<string, Exception, string>>()));

            var packets = userPrincipal.Packets(userspaceId);

            Assert.NotEmpty(packets);
            Assert.Single(packets);

            var packet = packets.First();
            Assert.Equal(packetId, packet.Id);

            var owner = packet.Owners.First();
            Assert.Equal(workGroupId, owner.WorkGroupId);
            Assert.Contains(userId, owner.Users);
        }
    }
}
