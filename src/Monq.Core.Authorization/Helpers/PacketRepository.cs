using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Monq.Core.Authorization.Models;

[assembly: InternalsVisibleTo("Monq.Core.Authorization.Tests")]

namespace Monq.Core.Authorization.Helpers
{
    /// <summary>
    /// Хранилище пакетов прав пользователей.
    /// </summary>
    internal static class PacketRepository
    {
        static readonly ConcurrentDictionary<long, CachedPacket> _packets
            = new ConcurrentDictionary<long, CachedPacket>();

        /// <summary>
        /// Получить пакеты прав по идентификатору пользователя.
        /// </summary>
        /// <param name="userId">Идентификатор пользователя.</param>
        /// <returns>Коллекция пакетов прав пользователя <see cref="IEnumerable{PacketViewModel}"/>.</returns>
        public static IEnumerable<PacketViewModel> Get(long userId)
            => _packets.TryGetValue(userId, out var cachedItem) ? cachedItem.Packets : Array.Empty<PacketViewModel>();

        /// <summary>
        /// Check the userId grants for the expiration.
        /// </summary>
        /// <param name="userId">User identifier.</param>
        /// <returns></returns>
        public static bool NotExistsOrExpired(long userId)
        {
            var item = _packets.TryGetValue(userId, out var cachedItem) ? cachedItem : null;
            return item is null || (item is not null && item.CacheTimeout is not null && DateTimeOffset.UtcNow - item.AddedAt > item.CacheTimeout)
                || (item is not null && item.CacheTimeout is null);
        }

        /// <summary>
        /// Установить соответствие пользователя с правом.
        /// </summary>
        /// <param name="userId">Идентификатор пользователя.</param>
        /// <param name="grant">Пакет прав пользователя <see cref="PacketViewModel"/>.</param>
        /// <param name="cacheTimeout">If set, the packet will be cached for <paramref name="cacheTimeout"/>.</param>
        public static void Set(long userId, PacketViewModel grant, TimeSpan? cacheTimeout = default)
            => _packets[userId] = new CachedPacket { Packets = new[] { grant }, AddedAt = DateTimeOffset.UtcNow, CacheTimeout = cacheTimeout };

        /// <summary>
        /// Установить соответствие пользователя с пакетом прав.
        /// </summary>
        /// <param name="userId">Идентификатор пользователя.</param>
        /// <param name="grants">Коллекция пакетов прав пользователя <see cref="IEnumerable{PacketViewModel}"/>.</param>
        /// <param name="cacheTimeout">If set, the packet will be cached for <paramref name="cacheTimeout"/>.</param>
        public static void Set(long userId, IEnumerable<PacketViewModel> grants, in TimeSpan? cacheTimeout = default)
            => _packets[userId] = new CachedPacket { Packets = grants, AddedAt = DateTimeOffset.UtcNow, CacheTimeout = cacheTimeout };
    }

    internal record CachedPacket
    {
        /// <summary>
        /// Список пакетов.
        /// </summary>
        public IEnumerable<PacketViewModel> Packets { get; init; } = Array.Empty<PacketViewModel>();

        /// <summary>
        /// Время добавления пакета в кэш.
        /// </summary>
        public DateTimeOffset AddedAt { get; init; }

        /// <summary>
        /// Таймаут кэша.
        /// </summary>
        public TimeSpan? CacheTimeout { get; init; }
    }
}
