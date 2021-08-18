using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Monq.Core.Authorization;
using Monq.Core.Authorization.Exceptions;
using Monq.Core.Authorization.Helpers;
using Monq.Core.Authorization.Models;

namespace Microsoft.AspNetCore.Authorization
{
    internal class GrantsExtensionsDefaultImpl : IGrantsExtensions
    {
        const sbyte SystemUserId = -1;
        const sbyte DefaultUserId = 0;

        const string SubjectClaim = "sub";
        const string ClientIdClaim = "client_id";
        const string ClientIdValue = "smon-res-owner";

        const string UserspaceIdHeader = "x-smon-userspace-id";

        /// <summary>
        /// Получить Id пользователя из <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <returns>Идентификатор пользователя, -1 для системного пользователя или 0, если неопределим.</returns>
        public long Subject(ClaimsPrincipal? user)
        {
            if (user is null)
                return DefaultUserId;

            var userSub = user.Claims.FirstOrDefault(x => x.Type == SubjectClaim)?.Value;

            if (string.IsNullOrWhiteSpace(userSub))
            {
                var isSystemUser = IsSystemUser(user);
                return isSystemUser ? SystemUserId : DefaultUserId;
            }

            return long.TryParse(userSub, out var userId) ? userId : DefaultUserId;
        }

        /// <summary>
        /// Получить права пользователя из <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <returns>Коллекция пакетов прав пользователя <see cref="IEnumerable{PacketViewModel}"/>.</returns>
        public IEnumerable<PacketViewModel> Packets(ClaimsPrincipal? user)
        {
            if (user is null)
                return Array.Empty<PacketViewModel>();

            var userId = user.Subject();
            if (userId <= 0)
                return Array.Empty<PacketViewModel>();

            var packets = PacketRepository.Get(userId);
            return packets;
        }

        /// <summary>
        /// Получить соответствие системного пакета.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="packetType">Тип системного пакета.</param>
        /// <returns>Идентификатор системного пакета.</returns>
        public long? GetSystemPacketId(ClaimsPrincipal? user, long userspaceId, PacketTypes packetType)
        {
            if (user is null)
                return null;

            var userId = user.Subject();
            if (userId <= 0)
                return null;

            var systemPacketMaps = PacketRepository.GetSystemPacketMaps(userId);
            return systemPacketMaps.FirstOrDefault(x => x.UserspaceId == userspaceId && x.PacketType == packetType)?.PacketId;
        }

        /// <summary>
        /// Проверить, есть ли заданное именем право у пользователя из <see cref="ClaimsPrincipal"/>.
        /// Всегда безусловно возвращает <c>true</c> для системного пользователя и администратора пространства.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="workGroupId">Идентификатор рабочей группы, в которой проверяется наличие прав.</param>
        /// <param name="grantName">Строковое представление права (например, "base-system.rsm.read").</param>
        /// <returns>Истина, если заданное право есть у пользователя запроса.</returns>
        public bool HasGrant(ClaimsPrincipal? user, long userspaceId, long workGroupId, string grantName)
            => HasAnyGrant(user, userspaceId, workGroupId, new[] { grantName });

        /// <summary>
        /// Проверить, есть ли хотя бы одно из заданных прав у пользователя из <see cref="ClaimsPrincipal"/>.
        /// Всегда безусловно возвращает <c>true</c> для системного пользователя и администратора пространства.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="workGroupId">Идентификатор рабочей группы, в которой проверяется наличие прав.</param>
        /// <param name="grantNames">Строковые представления прав (например, "base-system.rsm.read").</param>
        /// <returns>Истина, если хотя бы одно заданное право есть у пользователя запроса.</returns>
        public bool HasAnyGrant(ClaimsPrincipal? user, long userspaceId, long workGroupId, IEnumerable<string> grantNames)
        {
            if (IsSuperUser(user, userspaceId))
            {
                return true;
            }

            if (user is null || !grantNames.Any())
            {
                return false;
            }

            var packets = user.Packets();

            if (!packets.Any())
            {
                return false;
            }

            var userHasAnyGrant = packets
                .Where(val => grantNames.Any(val.Grants.Contains))  // Фильтруем пакеты по наличию (любого) права.
                .SelectMany(val => val.Owners)                      // Получаем владельцев оставшихся пакетов.
                .Any(val => val.WorkGroupId == workGroupId);        // И выясняем, является ли он сам искомой группой.
            return userHasAnyGrant;
        }

        /// <summary>
        /// Проверить, есть ли все заданные права у пользователя из <see cref="ClaimsPrincipal"/>.
        /// Всегда безусловно возвращает <c>true</c> для системного пользователя и администратора пространства.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="workGroupId">Идентификатор рабочей группы, в которой проверяется наличие прав.</param>
        /// <param name="grantNames">Строковые представления прав (например, "base-system.rsm.read").</param>
        /// <returns>Истина, если все заданные права есть у пользователя запроса.</returns>
        public bool HasAllGrants(ClaimsPrincipal? user, long userspaceId, long workGroupId, IEnumerable<string> grantNames)
        {
            if (IsSuperUser(user, userspaceId))
            {
                return true;
            }

            if (user is null || !grantNames.Any())
            {
                return false;
            }

            var packets = user.Packets();

            if (!packets.Any())
            {
                return false;
            }

            // Получить идентификаторы пакетов пользователя, имеющих права.
            // к релевантной рабочей группе.
            var workGroupRelatedPackets = packets
                .SelectMany(val => val.Owners)
                .Where(val => val.WorkGroupId == workGroupId)
                .Select(val => val.PacketId)
                .ToList();

            // Получить уникальные права в этих пакетах.
            var workGroupRelatedGrants = packets
                .Where(val => workGroupRelatedPackets.Contains(val.Id))
                .SelectMany(val => val.Grants)
                .Distinct()
                .ToList();

            // Проверить все запрашиваемые права в результирующей коллекции.
            var userHasAllGrants = grantNames.All(workGroupRelatedGrants.Contains);
            return userHasAllGrants;
        }

        /// <summary>
        /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/>
        /// администратором пользовательского пространства
        /// с данным идентификатором <paramref name="userspaceId"/>
        /// или обладает правом на пользовательские сущности.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <returns>Истина, если пользователь -- администратор заданного пользовательского пространства.</returns>
        public bool IsUserspaceAdmin(ClaimsPrincipal? user, long userspaceId)
        {
            var isUserspaceAdmin = IsUserspaceAdminAdmin(user, userspaceId);
            var hasUserEntitiesGrant = HasUsersEntitiesGrant(user, userspaceId);

            return isUserspaceAdmin || hasUserEntitiesGrant;
        }

        /// <summary>
        /// Проверить, есть ли у пользователя права к пользовательским сущностям.
        /// администратором пользовательского пространства
        /// с данным идентификатором <paramref name="userspaceId"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <returns>Истина, если пользователь -- администратор заданного пользовательского пространства.</returns>
        public bool HasUsersEntitiesGrant(ClaimsPrincipal? user, long userspaceId)
        {
            if (user is null)
                return false;

            var packets = user.Packets();

            if (!packets.Any())
                return false;

            var hasUserEntitiesGrant = packets
                .Where(val => val.Grants.Contains(Modules.GrantType.AdminsUserEntitiesWrite))
                .SelectMany(val => val.Owners)
                .Any(val => val.UserspaceId == userspaceId);

            return hasUserEntitiesGrant;
        }

        /// <summary>
        /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/>
        /// администратором пользовательского пространства с данным идентификатором <paramref name="userspaceId"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <returns>Истина, если пользователь -- администратор заданного пользовательского пространства.</returns>
        public bool IsUserspaceAdminAdmin(ClaimsPrincipal? user, long userspaceId)
        {
            if (user is null)
                return false;

            var packets = user.Packets();

            if (!packets.Any())
            {
                return false;
            }

            var userspaceAdminPacketId = user.GetSystemPacketId(userspaceId, PacketTypes.UserspaceAdmin);
            if (userspaceAdminPacketId.Equals(null))
                return false;

            var userHasCloudAdminGrantsInUserspace = packets
                .Where(val => val.Id == userspaceAdminPacketId)
                .SelectMany(val => val.Owners)
                .Any(val => val.UserspaceId == userspaceId);

            return userHasCloudAdminGrantsInUserspace;
        }

        /// <summary>
        /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/>
        /// системным пользователем.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <returns>Истина, если пользователь обладает аутентификационными данными системного.</returns>
        public bool IsSystemUser(ClaimsPrincipal? user)
        {
            if (user is null)
                return false;

            var userClientId = user.Claims.FirstOrDefault(x => x.Type == ClientIdClaim)?.Value;

            if (string.IsNullOrWhiteSpace(userClientId))
                return false;

            return string.Equals(userClientId, ClientIdValue, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/> системным или
        /// администратором пользовательского пространства с данным идентификатором <paramref name="userspaceId"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <returns>Истина, если пользователь -- cистемный или администратор заданного пользовательского пространства.</returns>
        public bool IsSuperUser(ClaimsPrincipal? user, long userspaceId)
            => IsSystemUser(user) || IsUserspaceAdmin(user, userspaceId);

        /// <summary>
        /// Получить Id рабочих групп, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть заданное именем право.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="grantName">Строковое представление права (например, "base-system.rsm.read").</param>
        /// <returns>
        /// Список идентификаторов рабочих групп, в которых у пользователя есть заданное право.
        /// </returns>
        public IEnumerable<long> GetWorkGroupsWithGrant(ClaimsPrincipal? user, long userspaceId, string grantName)
            => GetWorkGroupsWithAnyGrant(user, userspaceId, new[] { grantName });

        /// <summary>
        /// Получить Id рабочих групп, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть хотя бы одно из заданных прав.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="grantNames">Строковые представления прав (например, "base-system.rsm.read").</param>
        /// <returns>
        /// Список идентификаторов рабочих групп, в которых у пользователя есть заданное право.
        /// </returns>
        public IEnumerable<long> GetWorkGroupsWithAnyGrant(ClaimsPrincipal? user, long userspaceId, IEnumerable<string> grantNames)
        {
            if (user is null || !grantNames.Any())
            {
                return Array.Empty<long>();
            }

            var packets = user.Packets();

            if (!packets.Any())
            {
                return Array.Empty<long>();
            }

            var workGroupIds = packets
                .Where(val => grantNames.Any(val.Grants.Contains))
                .SelectMany(val => val.Owners)
                .Where(x => x.UserspaceId == userspaceId)
                .Select(val => val.WorkGroupId)
                .Distinct()
                .ToList();

            return workGroupIds;
        }

        /// <summary>
        /// Получить Id рабочих групп, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть все заданные права.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="grantNames">Строковые представления прав (например, "base-system.rsm.read").</param>
        /// <returns>
        /// Список идентификаторов рабочих групп, в которых у пользователя есть заданное право.
        /// </returns>
        public IEnumerable<long> GetWorkGroupsWithAllGrants(ClaimsPrincipal? user, long userspaceId, IEnumerable<string> grantNames)
        {
            if (user is null || !grantNames.Any())
            {
                return Array.Empty<long>();
            }

            var packets = user.Packets();

            if (!packets.Any())
            {
                return Array.Empty<long>();
            }

            var workGroupIds = packets
                .SelectMany(val => val.Owners)
                .Where(x => x.UserspaceId == userspaceId)
                .Select(val => val.WorkGroupId)
                .Distinct()
                .ToList();

            var workGroupGrants = workGroupIds
                .Select(workGroupId => (workGroupId, grants: packets
                    .Where(packet => packet.Owners
                        .Where(owner => owner.UserspaceId == userspaceId)
                        .Select(owner => owner.WorkGroupId)
                        .Contains(workGroupId))
                    .SelectMany(val => val.Grants)
                    .Distinct()))
                .ToList();

            var workGroupsWithAllGrants = workGroupGrants
                .Where(val => grantNames.All(val.grants.Contains))
                .Select(val => val.workGroupId)
                .OrderBy(val => val)
                .ToList();

            return workGroupsWithAllGrants;
        }

        /// <summary>
        /// Получить Id рабочих групп, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть какие-либо права.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <returns>Список идентификаторов рабочих групп, в которых у пользователя есть какое-либо право.</returns>
        public IEnumerable<long> WorkGroups(ClaimsPrincipal? user, long userspaceId)
            => Packets(user)
                .SelectMany(val => val.Owners)
                .Select(val => val.WorkGroupId)
                .Distinct()
                .ToList();

        /// <summary>
        /// Получить Id пространств пользователя, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть какие-либо права.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <returns>Список идентификаторов пространств пользователя, в которых у пользователя есть какое-либо право.</returns>
        public IEnumerable<long> Userspaces(ClaimsPrincipal? user)
            => Packets(user)
                .SelectMany(val => val.Owners)
                .Select(val => val.UserspaceId)
                .Distinct()
                .ToList();

        /// <summary>
        /// Получить Id пользовательского пространства из заголовков <see cref="HttpRequest"/> исполняемого запроса.
        /// </summary>
        /// <param name="request">Запрос из свойства Request в ControllerBase.</param>
        /// <returns>Идентификатор пользовательского пространства или 0, если неопределим.</returns>
        public long Userspace(HttpRequest request)
        {
            // Получаем первый из ключей заголовков, который в каком-нибудь регистре сходится с
            // ожидаемым, или null, если таких заголовков нет.
            var userspaceIdHeaderKey = request.Headers.Keys.FirstOrDefault(val =>
                string.Equals(val, UserspaceIdHeader, StringComparison.OrdinalIgnoreCase));

            if (string.IsNullOrWhiteSpace(userspaceIdHeaderKey))
            {
                throw new UserspaceNotFoundException($"Не указан заголовок {UserspaceIdHeader}.");
            }

            // Получаем значение полученным в верном регистре ключом.
            var userspaceIdHeaderValue = request.Headers[userspaceIdHeaderKey].FirstOrDefault();

            if (string.IsNullOrWhiteSpace(userspaceIdHeaderValue))
            {
                throw new UserspaceNotFoundException($"Не указан заголовок {UserspaceIdHeader}.");
            }

            if (!long.TryParse(userspaceIdHeaderValue, out var userspaceId))
            {
                throw new UserspaceNotFoundException($"Невозможно выполнить преобразование id пространства пользователя из заголовка {UserspaceIdHeader} в корректное значение.");
            }

            return userspaceId;
        }
    }
}
