using Microsoft.AspNetCore.Http;
using Monq.Core.Authorization;
using Monq.Core.Authorization.Exceptions;
using Monq.Core.Authorization.Helpers;
using Monq.Core.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

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
        /// <param name="userspaceId">Идентификатор userspace.</param>
        /// <returns>Коллекция пакетов прав пользователя <see cref="IEnumerable{PacketViewModel}"/>.</returns>
        public IEnumerable<PacketViewModel> Packets(ClaimsPrincipal? user, long userspaceId)
        {
            if (user is null)
                return Array.Empty<PacketViewModel>();

            var userId = user.Subject();
            if (userId <= 0)
                return Array.Empty<PacketViewModel>();

            var packets = PacketRepository.Get(userId, userspaceId.ToString(), user.ObjectKey());
            return packets;
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
                return true;

            if (user is null || !grantNames.Any())
                return false;

            var packets = user.Packets(userspaceId);

            // Проверка прав админ. панели.
            var adminPanelGrants = grantNames.Where(x => x.Contains(Modules.GrantType.AdminsGrantSuffix, StringComparison.Ordinal));
            if (adminPanelGrants?.Any() == true)
            {
                var hasAdminPanelPackets = HasAnyUserspaceAdminPanelGrant(user, userspaceId, adminPanelGrants);
                if (hasAdminPanelPackets) return true;
            }

            if (!packets.Any())
                return false;

            var userHasAnyGrant = packets
                .Where(val => grantNames.Any(val.Grants.Contains))  // Фильтруем пакеты по наличию (любого) права.
                .SelectMany(val => val.Owners)                      // Получаем владельцев оставшихся пакетов.
                .Any(val => val.WorkGroupId == workGroupId);        // И выясняем, является ли он сам искомой группой.
            return userHasAnyGrant;
        }

        /// <inheritdoc />
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

            var packets = user.Packets(userspaceId);

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

        /// <inheritdoc />
        public bool IsWorkGroupManager(ClaimsPrincipal user, long userspaceId, long workGroupId)
        {
            var packets = user.Packets(userspaceId);
            if (!packets.Any())
                return false;

            // Фильтруем по наличию у пользователя системного пакета WorkgroupManager.
            return packets
                .Any(val => val.Owners
                    .Any(owner => owner.WorkGroupId == workGroupId && owner.UserspaceId == userspaceId) 
                    && val.Type == PacketTypes.Manager);
        }

        /// <inheritdoc />
        public bool IsUserspaceAdmin(ClaimsPrincipal? user, long userspaceId)
            => HasUsersEntitiesGrant(user, userspaceId);

        public bool HasUsersEntitiesGrant(ClaimsPrincipal? user, long userspaceId)
        => HasUserspaceAdminPanelGrant(user, userspaceId, Modules.GrantType.AdminsUserEntitiesWrite);

        /// <inheritdoc />
        public bool HasUserspaceAdminPanelGrant(ClaimsPrincipal? user, long userspaceId, string adminPanelGrant)
            => HasAnyUserspaceAdminPanelGrant(user, userspaceId, new[] { adminPanelGrant });

        //// <inheritdoc />
        public bool HasAnyUserspaceAdminPanelGrant(ClaimsPrincipal? user, long userspaceId, IEnumerable<string> adminPanelGrantNames)
        {
            if (user is null || adminPanelGrantNames?.Any() != true)
                return false;

            var grants = adminPanelGrantNames.Where(x => x.Contains(Modules.GrantType.AdminsGrantSuffix, StringComparison.Ordinal));
            if (grants?.Any() != true)
                return false;

            var packets = user.Packets(userspaceId);
            if (!packets.Any())
                return false;

            var userHasAnyGrant = packets
                .Where(val => grants.Any(val.Grants.Contains))  // Фильтруем пакеты по наличию (любого) права.
                .SelectMany(val => val.Owners)                      // Получаем владельцев оставшихся пакетов.
                .Any(val => val.UserspaceId == userspaceId);        // И выясняем, находится ли владелец в пространстве.
            return userHasAnyGrant;
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
        /// <returns>Истина, если пользователь -- системный или администратор заданного пользовательского пространства.</returns>
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

            var packets = user.Packets(userspaceId);

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

            var packets = user.Packets(userspaceId);

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
            => Packets(user, userspaceId)
                .SelectMany(val => val.Owners)
                .Select(val => val.WorkGroupId)
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
                throw new UserspaceNotFoundException($"Header {UserspaceIdHeader} not defined.");
            }

            // Получаем значение полученным в верном регистре ключом.
            var userspaceIdHeaderValue = request.Headers[userspaceIdHeaderKey].FirstOrDefault();

            if (string.IsNullOrWhiteSpace(userspaceIdHeaderValue))
            {
                throw new UserspaceNotFoundException($"Header {UserspaceIdHeader} not defined.");
            }

            if (!long.TryParse(userspaceIdHeaderValue, out var userspaceId))
            {
                throw new UserspaceNotFoundException($"Unable to convert userspace ID from header {UserspaceIdHeader} to valid value.");
            }

            return userspaceId;
        }
    }
}
