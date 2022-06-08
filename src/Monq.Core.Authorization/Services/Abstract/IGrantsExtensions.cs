using System;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Security.Claims;
using Monq.Core.Authorization.Models;

namespace Microsoft.AspNetCore.Authorization
{
    /// <summary>
    /// Интерфейс описания методов расширения пользовательских прав для идентификаторов на основе утверждений
    /// (см. <see cref="ClaimsPrincipal"/>).
    /// </summary>
    public interface IGrantsExtensions
    {
        /// <summary>
        /// Получить Id пользователя из <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <returns>Идентификатор пользователя, -1 для системного пользователя или 0, если неопределим.</returns>
        long Subject(ClaimsPrincipal user);

        /// <summary>
        /// Получить права пользователя из <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор userspace.</param>
        /// <returns>Коллекция пакетов прав пользователя <see cref="IEnumerable{PacketViewModel}"/>.</returns>
        IEnumerable<PacketViewModel> Packets(ClaimsPrincipal user, long userspaceId);

        /// <summary>
        /// Проверить, есть ли заданное именем право у пользователя из <see cref="ClaimsPrincipal"/>.
        /// Всегда безусловно возвращает <c>true</c> для системного пользователя и администратора пространства.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="workGroupId">Идентификатор рабочей группы, в которой проверяется наличие прав.</param>
        /// <param name="grantName">Строковое представление права (например, "base-system.rsm.read").</param>
        /// <returns>Истина, если заданное право есть у пользователя запроса.</returns>
        bool HasGrant(ClaimsPrincipal user, long userspaceId, long workGroupId, string grantName);

        /// <summary>
        /// Проверить, есть ли хотя бы одно из заданных прав у пользователя из <see cref="ClaimsPrincipal"/>.
        /// Всегда безусловно возвращает <c>true</c> для системного пользователя и администратора пространства.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="workGroupId">Идентификатор рабочей группы, в которой проверяется наличие прав.</param>
        /// <param name="grantNames">Строковые представления прав (например, "base-system.rsm.read").</param>
        /// <returns>Истина, если хотя бы одно заданное право есть у пользователя запроса.</returns>
        bool HasAnyGrant(ClaimsPrincipal user, long userspaceId, long workGroupId, IEnumerable<string> grantNames);

        /// <summary>
        /// Проверить, есть ли все заданные права у пользователя из <see cref="ClaimsPrincipal"/>.
        /// Всегда безусловно возвращает <c>true</c> для системного пользователя и администратора пространства.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="workGroupId">Идентификатор рабочей группы, в которой проверяется наличие прав.</param>
        /// <param name="grantNames">Строковые представления прав (например, "base-system.rsm.read").</param>
        /// <returns>Истина, если все заданные права есть у пользователя запроса.</returns>
        bool HasAllGrants(ClaimsPrincipal user, long userspaceId, long workGroupId, IEnumerable<string> grantNames);

        /// <summary>
        /// Проверить, является ли пользователь с данным идентификатором <paramref name="userspaceId"/>
        /// из <see cref="ClaimsPrincipal"/> администратором пользовательского пространства 
        /// или обладает правом доступа к пользовательским сущностям.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <returns>Истина, если пользователь -- администратор заданного пользовательского пространства или обладает правом доступа к пользовательским сущностям.</returns>
        [Obsolete("Использовать HasUsersEntitiesGrant.")]
        bool IsUserspaceAdmin(ClaimsPrincipal user, long userspaceId);

        /// <summary>
        /// Проверить, есть ли у пользователя
        /// с данным идентификатором <paramref name="userspaceId"/>
        /// право доступа к пользовательским сущностям.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <returns>Истина, если у пользователя есть право доступа к пользовательским сущностям.</returns>
        bool HasUsersEntitiesGrant(ClaimsPrincipal user, long userspaceId);

        /// <summary>
        /// Проверить есть ли у пользователя
        /// с данным идентификатором <paramref name="userspaceId"/>
        /// парво из админ. панели.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="adminPanelGrant">Строковое представление права админ панели (например, "pl.admins.user-entities-write").</param>
        /// <returns>Истина при наличии права.</returns>
        bool HasUserspaceAdminPanelGrant(ClaimsPrincipal? user, long userspaceId, string adminPanelGrant);

        /// <summary>
        /// Проверить, есть ли хотя бы одно из заданных прав админ. панели у пользователя из <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="adminPanelGrantNames">Строковые представления прав админ. панели (например, "pl.admins.user-entities-write").</param>
        /// <returns>Истина, если хотя бы одно заданное право есть у пользователя запроса.</returns>
        bool HasAnyUserspaceAdminPanelGrant(ClaimsPrincipal? user, long userspaceId,
            IEnumerable<string> adminPanelGrantNames);

        /// <summary>
        /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/>
        /// системным пользователем.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <returns>Истина, если пользователь обладает аутентификационными данными системного.</returns>
        bool IsSystemUser(ClaimsPrincipal user);

        /// <summary>
        /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/> системным или
        /// администратором пользовательского пространства с данным идентификатором <paramref name="userspaceId"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <returns>Истина, если пользователь -- cистемный или администратор заданного пользовательского пространства.</returns>
        bool IsSuperUser(ClaimsPrincipal user, long userspaceId);

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
        IEnumerable<long> GetWorkGroupsWithGrant(ClaimsPrincipal user, long userspaceId, string grantName);

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
        IEnumerable<long> GetWorkGroupsWithAnyGrant(ClaimsPrincipal user, long userspaceId, IEnumerable<string> grantNames);

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
        IEnumerable<long> GetWorkGroupsWithAllGrants(ClaimsPrincipal user, long userspaceId, IEnumerable<string> grantNames);

        /// <summary>
        /// Получить Id рабочих групп, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть какие-либо права.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <returns>
        /// Список идентификаторов рабочих групп, в которых у пользователя есть какое-либо право.
        /// </returns>
        IEnumerable<long> WorkGroups(ClaimsPrincipal user, long userspaceId);

        /// <summary>
        /// Получить Id пользовательского пространства из заголовков <see cref="HttpRequest"/> исполняемого запроса.
        /// </summary>
        /// <param name="request">Запрос из свойства Request в ControllerBase.</param>
        /// <returns>Идентификатор пользовательского пространства или 0, если неопределим.</returns>
        long Userspace(HttpRequest request);
    }
}