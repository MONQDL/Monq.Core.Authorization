using System.Net.Http.Headers;

namespace Monq.Core.Authorization.Extensions
{
    /// <summary>
    /// Расширения для работы с заголовком запроса.
    /// </summary>
    public static class HttpRequestHeaderExtensions
    {
        /// <summary>
        /// Заменить или добавить указанный ключ в заголовок запроса.
        /// </summary>
        /// <param name="httpRequestHeaders"></param>
        /// <param name="name">Ключ.</param>
        /// <param name="value">Значение.</param>
        public static void TryUpdateWithoutValidation(this HttpRequestHeaders httpRequestHeaders, string name, string value)
        {
            if (httpRequestHeaders.Contains(name))
                httpRequestHeaders.Remove(name);

            if (string.IsNullOrEmpty(value)) return;

            httpRequestHeaders.TryAddWithoutValidation(name, value);
        }

        /// <summary>
        /// Добавить указанный ключ в заголовок запроса, если такого еще нет.
        /// </summary>
        /// <param name="httpRequestHeaders"></param>
        /// <param name="name">Ключ.</param>
        /// <param name="value">Значение.</param>
        public static void TryAddIfNotContain(this HttpRequestHeaders httpRequestHeaders, string name, string value)
        {
            if (httpRequestHeaders.Contains(name)) return;
            httpRequestHeaders.TryAddWithoutValidation(name, value);
        }
    }
}
