using Monq.Core.Authorization.Models;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Monq.Core.Authorization.Tests")]

namespace Monq.Core.Authorization.Helpers
{
    /// <summary>
    /// Хранилище пакетов прав пользователей.
    /// </summary>
    internal static class PacketRepository
    {
        static readonly ConcurrentDictionary<CachedUser, CachedPacket> _packets
            = new ConcurrentDictionary<CachedUser, CachedPacket>();

        /// <summary>
        /// Get permission packets by user ID.
        /// </summary>
        /// <param name="userId">User identifier.</param>
        /// <param name="userspaceId">Userspace identifier.</param>
        /// <param name="key">Object key.</param>
        /// <returns>Collection of user packets <see cref="IEnumerable{PacketViewModel}"/>.</returns>
        public static IEnumerable<PacketViewModel> Get(long userId, string? userspaceId, string? key)
            => _packets.TryGetValue(new CachedUser { UserId = userId, UserspaceId = userspaceId, Key = key}, out var cachedItem) ? cachedItem.Packets : Array.Empty<PacketViewModel>();

        /// <summary>
        /// Check the userId grants for the expiration.
        /// </summary>
        /// <param name="userId">User identifier.</param>
        /// <param name="userspaceId">Userspace identifier.</param>
        /// <param name="key">Object key.</param>
        /// <returns></returns>
        public static bool NotExistsOrExpired(long userId, string? userspaceId, string? key)
        {
            var item = _packets.TryGetValue(new CachedUser { UserId = userId, UserspaceId = userspaceId, Key = key }, out var cachedItem) ? cachedItem : null;
            return item is null || (item is not null && item.CacheTimeout is not null && DateTimeOffset.UtcNow - item.AddedAt > item.CacheTimeout)
                || (item is not null && item.CacheTimeout is null);
        }

        /// <summary>
        /// Match the user with the right.
        /// </summary>
        /// <param name="userId">User identifier.</param>
        /// <param name="userspaceId">Userspace identifier.</param>
        /// <param name="key">Object key.</param>
        /// <param name="grant">User's grant <see cref="PacketViewModel"/>.</param>
        /// <param name="cacheTimeout">If set, the packet will be cached for <paramref name="cacheTimeout"/>.</param>
        public static void Set(long userId, string? userspaceId, string? key, PacketViewModel grant, TimeSpan? cacheTimeout = default)
            => _packets[new CachedUser { UserId = userId, UserspaceId = userspaceId, Key = key}] = new CachedPacket { Packets = new[] { grant }, AddedAt = DateTimeOffset.UtcNow, CacheTimeout = cacheTimeout };

        /// <summary>
        /// Установить соответствие пользователя с пакетом прав.
        /// </summary>
        /// <param name="userId">User identifier.</param>
        /// <param name="userspaceId">Userspace identifier.</param>
        /// <param name="key">Object key.</param>
        /// <param name="grants">Collection of user packets <see cref="IEnumerable{PacketViewModel}"/>.</param>
        /// <param name="cacheTimeout">If set, the packet will be cached for <paramref name="cacheTimeout"/>.</param>
        public static void Set(long userId, string? userspaceId, string? key, IEnumerable<PacketViewModel> grants, in TimeSpan? cacheTimeout = default)
            => _packets[new CachedUser { UserId = userId, UserspaceId = userspaceId, Key = key }] = new CachedPacket { Packets = grants, AddedAt = DateTimeOffset.UtcNow, CacheTimeout = cacheTimeout };
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

    internal record CachedUser
    {
        /// <summary>
        /// User identifier.
        /// </summary>
        public long UserId { get; init; }

        /// <summary>
        /// Userspace identifier.
        /// </summary>
        public string? UserspaceId { get; init; }

        /// <summary>
        /// Object key.
        /// </summary>
        public string? Key { get; init; }
    }
}
