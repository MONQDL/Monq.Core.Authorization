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
        static readonly ConcurrentDictionary<long, IEnumerable<PacketViewModel>> _packets
            = new ConcurrentDictionary<long, IEnumerable<PacketViewModel>>();

        static readonly ConcurrentDictionary<long, IEnumerable<SystemPacketMapViewModel>> _systemPacketMaps
            = new ConcurrentDictionary<long, IEnumerable<SystemPacketMapViewModel>>();
        
        /// <summary>
        /// Получить пакеты прав по идентификатору пользователя.
        /// </summary>
        /// <param name="userId">Идентификатор пользователя.</param>
        /// <returns>Коллекция пакетов прав пользователя <see cref="IEnumerable{PacketViewModel}"/>.</returns>
        public static IEnumerable<PacketViewModel> Get(in long userId)
            => _packets.TryGetValue(userId, out var packets) ? packets : Array.Empty<PacketViewModel>();

        /// <summary>
        /// Получить соответствия системных пакетов прав.
        /// </summary>
        /// <returns>Коллекция соответствий системных пакетов прав <see cref="IEnumerable{SystemPacketMapViewModel}"/>.</returns>
        public static IEnumerable<SystemPacketMapViewModel> GetSystemPacketMaps(in long userId)
            => _systemPacketMaps.TryGetValue(userId, out var systemPacketMaps) ? systemPacketMaps : Array.Empty<SystemPacketMapViewModel>();

        /// <summary>
        /// Установить соответствие пользователя с правом.
        /// </summary>
        /// <param name="userId">Идентификатор пользователя.</param>
        /// <param name="grant">Пакет прав пользователя <see cref="PacketViewModel"/>.</param>
        public static void Set(in long userId, in PacketViewModel grant)
            => _packets[userId] = new[] { grant };

        /// <summary>
        /// Установить соответствие пользователя с пакетом прав.
        /// </summary>
        /// <param name="userId">Идентификатор пользователя.</param>
        /// <param name="grants">Коллекция пакетов прав пользователя <see cref="IEnumerable{PacketViewModel}"/>.</param>
        public static void Set(in long userId, in IEnumerable<PacketViewModel> grants)
            => _packets[userId] = grants;

        /// <summary>
        /// Установить соответствие системных пакетов прав.
        /// </summary>
        /// <param name="userId">Идентификатор пользователя.</param>
        /// <param name="systemPacketMaps">Коллекция соответствия для системных пакетов прав <see cref="IEnumerable{SystemPacketMapViewModel}"/>.</param>
        public static void SetSystemPacketMaps(in long userId, in IEnumerable<SystemPacketMapViewModel> systemPacketMaps)
            => _systemPacketMaps[userId] = systemPacketMaps;
    }
}
