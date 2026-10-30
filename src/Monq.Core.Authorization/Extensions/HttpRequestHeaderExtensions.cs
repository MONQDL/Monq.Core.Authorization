using System.Net.Http.Headers;

namespace Monq.Core.Authorization.Extensions;

/// <summary>
/// Extensions for working with request headers.
/// </summary>
public static class HttpRequestHeaderExtensions
{
    /// <summary>
    /// Replaces or adds the specified key in the request header.
    /// </summary>
    /// <param name="httpRequestHeaders"></param>
    /// <param name="name">The key.</param>
    /// <param name="value">The value.</param>
    public static void TryUpdateWithoutValidation(this HttpRequestHeaders httpRequestHeaders, string name, string value)
    {
        if (httpRequestHeaders.Contains(name))
            httpRequestHeaders.Remove(name);

        if (string.IsNullOrEmpty(value)) return;

        httpRequestHeaders.TryAddWithoutValidation(name, value);
    }

    /// <summary>
    /// Adds the specified key to the request header if it is not yet present.
    /// </summary>
    /// <param name="httpRequestHeaders"></param>
    /// <param name="name">The key.</param>
    /// <param name="value">The value.</param>
    public static void TryAddIfNotContain(this HttpRequestHeaders httpRequestHeaders, string name, string value)
    {
        if (httpRequestHeaders.Contains(name)) return;
        httpRequestHeaders.TryAddWithoutValidation(name, value);
    }
}
