using Microsoft.AspNetCore.Http;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Monq.Core.Authorization.Extensions
{
    public static class HttpContextExtensions
    {
        const string Authorization = "Authorization";
        const string UserspaceId = "x-smon-userspace-id";
        const string Bearer = "Bearer";

        /// <summary>
        /// Get access token from HttpContext request header.
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

        /// <summary>
        /// Get UserpaceId from the HttpContext request header.
        /// </summary>
        /// <param name="context">The context.</param>
        public static Task<string> GetUserspaceId(this HttpContext context)
        {
            var userspaceHeader = context.Request.Headers[UserspaceId].FirstOrDefault();
            return Task.FromResult(userspaceHeader ?? string.Empty);
        }
    }
}
