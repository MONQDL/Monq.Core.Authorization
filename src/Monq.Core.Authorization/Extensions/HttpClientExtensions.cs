using System.Net.Http;
using System.Net.Http.Headers;

namespace Monq.Core.Authorization.Extensions;

internal static class HttpClientExtensions
{
    const string Bearer = "Bearer";
    const string UserspaceIdHeader = "x-smon-userspace-id";

    internal static void SetBearerToken(this HttpClient client, string token)
        => client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(Bearer, token);

    internal static void SetUserspaceId(this HttpClient client, string userspaceId)
    {
        if (client.DefaultRequestHeaders.Contains(UserspaceIdHeader))
            return;
        client.DefaultRequestHeaders.TryAddWithoutValidation(UserspaceIdHeader, userspaceId);
    }
}
