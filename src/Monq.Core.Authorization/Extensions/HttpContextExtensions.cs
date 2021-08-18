using Microsoft.AspNetCore.Http;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Monq.Core.Authorization.Extensions
{
    public static class HttpContextExtensions
    {
        const string Authorization = "Authorization";
        const string Bearer = "Bearer";

        /// <summary>
        /// Получить access token из заголовка запроса HttpContext.
        /// </summary>
        /// <param name="context">The context.</param>
        public static Task<string> GetToken(this HttpContext context)
        {
            var authHeader = context.Request.Headers[Authorization].FirstOrDefault();
            if (authHeader is null)
            {
                return Task.FromResult(string.Empty);
            }

            if (!authHeader.StartsWith(Bearer, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(string.Empty);
            }

            var token = authHeader.Replace(Bearer, string.Empty).TrimStart();
            return Task.FromResult(token);
        }
    }
}
