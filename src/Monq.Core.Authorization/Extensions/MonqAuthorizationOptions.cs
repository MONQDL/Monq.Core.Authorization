using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace Monq.Core.Authorization.Extensions
{
    public sealed class MonqAuthorizationOptions
    {
        /// <summary>
        /// Делегат вызывается каждый раз при попытке получить Access token.
        /// </summary>
        public Func<HttpContext, Task<string>>? GetAccessToken { get; set; }

        /// <summary>
        /// Делегат для извлечения идентификатора пользовательского пространства из HTTP контекста.
        /// </summary>
        public Func<HttpContext, Task<string>>? GetUserspaceId { get; set; }

        /// <summary>
        /// Если <c>true</c>, то список прав пользователя будет кэширован на <see cref="CacheTime"/>.
        /// </summary>
        public bool UseCache { get; set; } = true;

        /// <summary>
        /// Длительность кэширования прав пользователя, если <see cref="UseCache"/> = <c>true</c>. По умолчанию - 3 сек.
        /// </summary>
        public TimeSpan CacheTime { get; set; } = TimeSpan.FromSeconds(3);
    }
}
