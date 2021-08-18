using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Security.Claims;
using Monq.Core.Authorization.Models;

namespace Microsoft.AspNetCore.Authorization
{
    /// <summary>
    /// Расширения для работы с идентификаторами на основе утверждений.
    /// </summary>
    public static class GrantsExtensions
    {
        /// <summary>
        /// Реализация методов расширения пользовательских прав.
        /// </summary>
        public static IGrantsExtensions Implementation { get; set; }
            = new GrantsExtensionsDefaultImpl();

        /// <summary>
        /// Получить Id пользователя из <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <returns>Идентификатор пользователя, -1 для системного пользователя или 0, если неопределим.</returns>
        public static long Subject(this ClaimsPrincipal user)
            => Implementation.Subject(user);

        /// <summary>
        /// Получить права пользователя из <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <returns>Коллекция пакетов прав пользователя <see cref="IEnumerable{PacketViewModel}"/>.</returns>
        public static IEnumerable<PacketViewModel> Packets(this ClaimsPrincipal user)
            => Implementation.Packets(user);

        /// <summary>
        /// Получить соответствие системного пакета.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="packetType">Тип системного пакета.</param>
        /// <returns>Идентификатор системного пакета.</returns>
        public static long? GetSystemPacketId(this ClaimsPrincipal user, long userspaceId, PacketTypes packetType) =>
            Implementation.GetSystemPacketId(user, userspaceId, packetType);

        /// <summary>
        /// Проверить, есть ли заданное именем право у пользователя из <see cref="ClaimsPrincipal"/>.
        /// Всегда безусловно возвращает <c>true</c> для системного пользователя и администратора пространства.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="workGroupId">Идентификатор рабочей группы, в которой проверяется наличие прав.</param>
        /// <param name="grantName">Строковое представление права (например, "base-system.rsm.read").</param>
        /// <returns>Истина, если заданное право есть у пользователя запроса.</returns>
        public static bool HasGrant(this ClaimsPrincipal user, in long userspaceId, in long workGroupId, in string grantName)
            => Implementation.HasGrant(user, userspaceId, workGroupId, grantName);

        /// <summary>
        /// Проверить, есть ли хотя бы одно из заданных прав у пользователя из <see cref="ClaimsPrincipal"/>.
        /// Всегда безусловно возвращает <c>true</c> для системного пользователя и администратора пространства.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="workGroupId">Идентификатор рабочей группы, в которой проверяется наличие прав.</param>
        /// <param name="grantNames">Строковые представления прав (например, "base-system.rsm.read").</param>
        /// <returns>Истина, если хотя бы одно заданное право есть у пользователя запроса.</returns>
        public static bool HasAnyGrant(this ClaimsPrincipal user, in long userspaceId, in long workGroupId, in IEnumerable<string> grantNames)
            => Implementation.HasAnyGrant(user, userspaceId, workGroupId, grantNames);

        /// <summary>
        /// Проверить, есть ли все заданные права у пользователя из <see cref="ClaimsPrincipal"/>.
        /// Всегда безусловно возвращает <c>true</c> для системного пользователя и администратора пространства.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="workGroupId">Идентификатор рабочей группы, в которой проверяется наличие прав.</param>
        /// <param name="grantNames">Строковые представления прав (например, "base-system.rsm.read").</param>
        /// <returns>Истина, если все заданные права есть у пользователя запроса.</returns>
        public static bool HasAllGrants(this ClaimsPrincipal user, in long userspaceId, in long workGroupId, in IEnumerable<string> grantNames)
            => Implementation.HasAllGrants(user, userspaceId, workGroupId, grantNames);

        /// <summary>
        /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/>
        /// администратором пользовательского пространства с данным идентификатором <paramref name="userspaceId"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <returns>Истина, если пользователь -- администратор заданного пользовательского пространства.</returns>
        public static bool IsUserspaceAdmin(this ClaimsPrincipal user, in long userspaceId)
            => Implementation.IsUserspaceAdmin(user, userspaceId);

        /// <summary>
        /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/>
        /// системным пользователем.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <returns>Истина, если пользователь обладает аутентификационными данными системного.</returns>
        public static bool IsSystemUser(this ClaimsPrincipal user)
            => Implementation.IsSystemUser(user);

        /// <summary>
        /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/> системным или
        /// администратором пользовательского пространства с данным идентификатором <paramref name="userspaceId"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <returns>Истина, если пользователь -- cистемный или администратор заданного пользовательского пространства.</returns>
        public static bool IsSuperUser(this ClaimsPrincipal user, in long userspaceId)
            => Implementation.IsSuperUser(user, userspaceId);

        /// <summary>
        /// Получить Id рабочих групп, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть заданное именем право.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Id пользовательского пространства.</param>
        /// <param name="grantName">Строковое представление права (например, "base-system.rsm.read").</param>
        /// <returns>
        /// Список идентификаторов рабочих групп, в которых у пользователя есть заданное право.
        /// </returns>
        public static IEnumerable<long> GetWorkGroupsWithGrant(this ClaimsPrincipal user, in long userspaceId, in string grantName)
            => Implementation.GetWorkGroupsWithGrant(user, userspaceId, grantName);

        /// <summary>
        /// Получить Id рабочих групп, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть хотя бы одно из заданных прав.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Id пользовательского пространства.</param>
        /// <param name="grantNames">Строковые представления прав (например, "base-system.rsm.read").</param>
        /// <returns>
        /// Список идентификаторов рабочих групп, в которых у пользователя есть заданное право.
        /// </returns>
        public static IEnumerable<long> GetWorkGroupsWithAnyGrant(this ClaimsPrincipal user, in long userspaceId, in IEnumerable<string> grantNames)
            => Implementation.GetWorkGroupsWithAnyGrant(user, userspaceId, grantNames);

        /// <summary>
        /// Получить Id рабочих групп, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть все заданные права.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Id пользовательского пространства.</param>
        /// <param name="grantNames">Строковые представления прав (например, "base-system.rsm.read").</param>
        /// <returns>
        /// Список идентификаторов рабочих групп, в которых у пользователя есть заданное право.
        /// </returns>
        public static IEnumerable<long> GetWorkGroupsWithAllGrants(this ClaimsPrincipal user, in long userspaceId, in IEnumerable<string> grantNames)
            => Implementation.GetWorkGroupsWithAllGrants(user, userspaceId, grantNames);

        /// <summary>
        /// Получить Id рабочих групп, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть какие-либо права.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Id пользовательского пространства.</param>
        /// <returns>
        /// Список идентификаторов рабочих групп, в которых у пользователя есть какое-либо право.
        /// </returns>
        public static IEnumerable<long> WorkGroups(this ClaimsPrincipal user, in long userspaceId)
            => Implementation.WorkGroups(user, userspaceId);

        /// <summary>
        /// Получить Id пространств пользователя, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть какие-либо права.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <returns>Список идентификаторов пространств пользователя, в которых у пользователя есть какое-либо право.</returns>
        public static IEnumerable<long> Userspaces(this ClaimsPrincipal user)
            => Implementation.Userspaces(user);

        /// <summary>
        /// Получить Id пользовательского пространства из заголовков <see cref="HttpRequest"/> исполняемого запроса.
        /// </summary>
        /// <param name="request">Запрос из свойства Request в ControllerBase.</param>
        /// <returns>Идентификатор пользовательского пространства или 0, если неопределим.</returns>
        public static long Userspace(this HttpRequest request)
            => Implementation.Userspace(request);
    }
}
