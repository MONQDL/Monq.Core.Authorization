using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace Monq.Core.Authorization.Extensions
{
    public class MonqAuthorizationOptions
    {
        /// <summary>
        /// Делегат вызывается каждый раз при попытке получить Access token.
        /// </summary>
        public Func<HttpContext, Task<string>> GetAccessToken { get; set; }

        /// <summary>
        /// Делегат для извлечения идентификатора пользовательского пространства из HTTP контекста.
        /// </summary>
        public Func<HttpContext, Task<string>> GetUserspaceId { get; set; }
    }
}
