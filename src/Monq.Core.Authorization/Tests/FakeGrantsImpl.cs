using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using Monq.Core.Authorization.Models;

namespace Monq.Core.Authorization.Tests
{
    /// <summary>
    /// Эталонная реализация тестового представления методов расширения пользовательских прав
    /// для идентификаторов на основе утверждений (см. <see cref="IGrantsExtensions"/>).
    /// </summary>
    public class FakeGrantsImpl : IGrantsExtensions
    {
        readonly GrantsExtensionsDefaultImpl _defaultImpl
            = new GrantsExtensionsDefaultImpl();

        /// <summary>
        /// Получить коллекцию пакетов прав пользователя из <see cref="ClaimsPrincipal"/>.
        /// </summary>
        public Func<ClaimsPrincipal, IEnumerable<PacketViewModel>>? PacketsFunc { get; set; }

        /// <summary>
        /// Проверить, есть ли все заданные права у пользователя из <see cref="ClaimsPrincipal"/>.
        /// </summary>
        public Func<ClaimsPrincipal, long, long, IEnumerable<string>, bool>? HasAllGrantsFunc { get; set; }

        /// <summary>
        /// Проверить, есть ли хотя бы одно из заданных прав у пользователя из <see cref="ClaimsPrincipal"/>.
        /// </summary>
        public Func<ClaimsPrincipal, long, long, IEnumerable<string>, bool>? HasAnyGrantFunc { get; set; }

        /// <summary>
        /// Проверить, есть ли заданное именем право у пользователя из <see cref="ClaimsPrincipal"/>.
        /// </summary>
        public Func<ClaimsPrincipal, long, long, string, bool>? HasGrantFunc { get; set; }

        /// <summary>
        /// Получить Id пользователя из <see cref="ClaimsPrincipal"/>.
        /// </summary>
        public Func<ClaimsPrincipal, long>? SubjectFunc { get; set; }

        /// <summary>
        /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/>
        /// администратором пользовательского пространства с данным идентификатором.
        /// </summary>
        [Obsolete("Использовать IsAllowUserEntities. " +
                  "Для проверки наличия только пакета администратора использовать HasUserspaceAdminPacket. " +
                  "Для проверки наличия только права доступа к пользовательским сущностям использовать HasUsersEntitiesGrant.")]
        public Func<ClaimsPrincipal, long, bool>? IsUserspaceAdminFunc { get; set; }

        /// <summary>
        /// Проверить, есть ли у пользователь
        /// из <see cref="ClaimsPrincipal"/> доступ к пользовательским сущностям.
        /// </summary>
        public Func<ClaimsPrincipal, long, bool>? IsAllowUserEntitiesFunc { get; set; }

        /// <summary>
        /// Проверить, есть ли у пользователь
        /// из <see cref="ClaimsPrincipal"/> доступ к пользовательским сущностям.
        /// </summary>
        public Func<ClaimsPrincipal, long, bool>? HasUserspaceAdminPacketFunc { get; set; }

        /// <summary>
        /// Проверить, есть ли у пользователь
        /// из <see cref="ClaimsPrincipal"/> доступ к пользовательским сущностям.
        /// </summary>
        public Func<ClaimsPrincipal, long, bool>? HasUsersEntitiesGrantFunc { get; set; }

        /// <summary>
        /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/>
        /// системным пользователем.
        /// </summary>
        public Func<ClaimsPrincipal, bool>? IsSystemUserFunc { get; set; }

        /// <summary>
        /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/> системным или
        /// администратором пользовательского пространства с данным идентификатором.
        /// </summary>
        public Func<ClaimsPrincipal, long, bool>? IsSuperUserFunc { get; set; }

        /// <summary>
        /// Получить Id рабочих групп, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть заданное именем право.
        /// </summary>
        public Func<ClaimsPrincipal, long, string, IEnumerable<long>>? GetWorkGroupsWithGrantFunc { get; set; }

        /// <summary>
        /// Получить Id рабочих групп, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть хотя бы одно из заданных прав.
        /// </summary>
        public Func<ClaimsPrincipal, long, IEnumerable<string>, IEnumerable<long>>? GetWorkGroupsWithAnyGrantFunc { get; set; }

        /// <summary>
        /// Получить Id рабочих групп, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть все заданные права.
        /// </summary>
        public Func<ClaimsPrincipal, long, IEnumerable<string>, IEnumerable<long>>? GetWorkGroupsWithAllGrantsFunc { get; set; }

        /// <summary>
        /// Получить Id рабочих групп, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть какие-либо права.
        /// </summary>
        public Func<ClaimsPrincipal, long, IEnumerable<long>>? WorkGroupsFunc { get; set; }

        /// <summary>
        /// Получить Id пространств пользователя, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть какие-либо права.
        /// </summary>
        public Func<ClaimsPrincipal, IEnumerable<long>>? UserspacesFunc { get; set; }

        /// <summary>
        /// Получить Id пользовательского пространства из заголовков <see cref="HttpRequest"/> исполняемого запроса.
        /// </summary>
        public Func<HttpRequest, long>? UserspaceFunc { get; set; }

        /// <summary>
        /// Получить права пользователя из <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <returns>Коллекция пакетов прав пользователя <see cref="IEnumerable{PacketViewModel}"/>.</returns>
        public IEnumerable<PacketViewModel> Packets(ClaimsPrincipal user) =>
            PacketsFunc?.Invoke(user) ?? _defaultImpl.Packets(user);


        /// <summary>
        /// Получить соответствие системного пакета.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="packetType">Тип системного пакета.</param>
        /// <returns>Идентификатор системного пакета.</returns>
        public long? GetSystemPacketId(ClaimsPrincipal user, long userspaceId, PacketTypes packetType) =>
            _defaultImpl.GetSystemPacketId(user, userspaceId, packetType);

        /// <summary>
        /// Проверить, есть ли все заданные права у пользователя из <see cref="ClaimsPrincipal"/>.
        /// Всегда безусловно возвращает <c>true</c> для системного пользователя и администратора пространства.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="workGroupId">Идентификатор рабочей группы, в которой проверяется наличие прав.</param>
        /// <param name="grantNames">Строковые представления прав (например, "base-system.rsm.read").</param>
        /// <returns>Истина, если все заданные права есть у пользователя запроса.</returns>
        public bool HasAllGrants(ClaimsPrincipal user, long userspaceId, long workGroupId, IEnumerable<string> grantNames) =>
            HasAllGrantsFunc?.Invoke(user, userspaceId, workGroupId, grantNames) ?? _defaultImpl.HasAllGrants(user, userspaceId, workGroupId, grantNames);

        /// <summary>
        /// Проверить, есть ли хотя бы одно из заданных прав у пользователя из <see cref="ClaimsPrincipal"/>.
        /// Всегда безусловно возвращает <c>true</c> для системного пользователя и администратора пространства.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="workGroupId">Идентификатор рабочей группы, в которой проверяется наличие прав.</param>
        /// <param name="grantNames">Строковые представления прав (например, "base-system.rsm.read").</param>
        /// <returns>Истина, если хотя бы одно заданное право есть у пользователя запроса.</returns>
        public bool HasAnyGrant(ClaimsPrincipal user, long userspaceId, long workGroupId, IEnumerable<string> grantNames) =>
            HasAnyGrantFunc?.Invoke(user, userspaceId, workGroupId, grantNames) ?? _defaultImpl.HasAnyGrant(user, userspaceId, workGroupId, grantNames);

        /// <summary>
        /// Проверить, есть ли заданное именем право у пользователя из <see cref="ClaimsPrincipal"/>.
        /// Всегда безусловно возвращает <c>true</c> для системного пользователя и администратора пространства.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <param name="workGroupId">Идентификатор рабочей группы, в которой проверяется наличие прав.</param>
        /// <param name="grantName">Строковое представление права (например, "base-system.rsm.read").</param>
        /// <returns>Истина, если заданное право есть у пользователя запроса.</returns>
        public bool HasGrant(ClaimsPrincipal user, long userspaceId, long workGroupId, string grantName) =>
            HasGrantFunc?.Invoke(user, userspaceId, workGroupId, grantName) ?? _defaultImpl.HasGrant(user, userspaceId, workGroupId, grantName);


        /// <inheritdoc />
        [Obsolete("Использовать IsAllowUserEntities. " +
                  "Для проверки наличия только пакета администратора использовать HasUserspaceAdminPacket. " +
                  "Для проверки наличия только права к пользовательским сущностям использовать HasUsersEntitiesGrant.")]
        public bool IsUserspaceAdmin(ClaimsPrincipal user, long userspaceId) =>
            IsUserspaceAdminFunc?.Invoke(user, userspaceId) ?? _defaultImpl.IsUserspaceAdmin(user, userspaceId);

        /// <inheritdoc />
        public bool IsAllowUserEntities(ClaimsPrincipal user, long userspaceId) =>
            IsAllowUserEntitiesFunc?.Invoke(user, userspaceId) ?? _defaultImpl.IsAllowUserEntities(user, userspaceId);

        /// <inheritdoc />
        public bool HasUserspaceAdminPacket(ClaimsPrincipal user, long userspaceId) =>
            HasUserspaceAdminPacketFunc?.Invoke(user, userspaceId) ?? _defaultImpl.HasUserspaceAdminPacket(user, userspaceId);

        /// <inheritdoc />
        public bool HasUsersEntitiesGrant(ClaimsPrincipal user, long userspaceId) =>
            HasUsersEntitiesGrantFunc?.Invoke(user, userspaceId) ?? _defaultImpl.HasUsersEntitiesGrant(user, userspaceId);

        /// <summary>
        /// Получить Id пользователя из <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <returns>Идентификатор пользователя или -1 для системного пользователя.</returns>
        public long Subject(ClaimsPrincipal user) =>
            SubjectFunc?.Invoke(user) ?? _defaultImpl.Subject(user);

        /// <summary>
        /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/> системным или
        /// администратором пользовательского пространства с данным идентификатором <paramref name="userspaceId"/>.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <returns>Истина, если пользователь -- cистемный или администратор заданного пользовательского пространства.</returns>
        public bool IsSuperUser(ClaimsPrincipal user, long userspaceId) =>
            IsSuperUserFunc?.Invoke(user, userspaceId) ?? _defaultImpl.IsSuperUser(user, userspaceId);

        /// <summary>
        /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/>
        /// системным пользователем.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <returns>Истина, если пользователь обладает аутентификационными данными системного.</returns>
        public bool IsSystemUser(ClaimsPrincipal user) =>
            IsSystemUserFunc?.Invoke(user) ?? _defaultImpl.IsSystemUser(user);

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
        public IEnumerable<long> GetWorkGroupsWithGrant(ClaimsPrincipal user, long userspaceId, string grantName) =>
            GetWorkGroupsWithGrantFunc?.Invoke(user, userspaceId, grantName) ?? _defaultImpl.GetWorkGroupsWithGrant(user, userspaceId, grantName);

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
        public IEnumerable<long> GetWorkGroupsWithAnyGrant(ClaimsPrincipal user, long userspaceId, IEnumerable<string> grantNames) =>
            GetWorkGroupsWithAnyGrantFunc?.Invoke(user, userspaceId, grantNames) ?? _defaultImpl.GetWorkGroupsWithAnyGrant(user, userspaceId, grantNames);

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
        public IEnumerable<long> GetWorkGroupsWithAllGrants(ClaimsPrincipal user, long userspaceId, IEnumerable<string> grantNames) =>
            GetWorkGroupsWithAllGrantsFunc?.Invoke(user, userspaceId, grantNames) ?? _defaultImpl.GetWorkGroupsWithAllGrants(user, userspaceId, grantNames);

        /// <summary>
        /// Получить Id рабочих групп, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть какие-либо права.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
        /// <returns>Список идентификаторов рабочих групп, в которых у пользователя есть какое-либо право.</returns>
        public IEnumerable<long> WorkGroups(ClaimsPrincipal user, long userspaceId) =>
            WorkGroupsFunc?.Invoke(user, userspaceId) ?? _defaultImpl.WorkGroups(user, userspaceId);

        /// <summary>
        /// Получить Id пространств пользователя, в которых у пользователя из <see cref="ClaimsPrincipal"/>
        /// есть какие-либо права.
        /// </summary>
        /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
        /// <returns>Список идентификаторов пространств пользователя, в которых у пользователя есть какое-либо право.</returns>
        public IEnumerable<long> Userspaces(ClaimsPrincipal user) =>
            UserspacesFunc?.Invoke(user) ?? _defaultImpl.Userspaces(user);

        /// <summary>
        /// Получить Id пользовательского пространства из заголовков <see cref="HttpRequest"/> исполняемого запроса.
        /// </summary>
        /// <param name="request">Запрос из свойства Request в ControllerBase.</param>
        /// <returns>Идентификатор пользовательского пространства или 0, если неопределим.</returns>
        public long Userspace(HttpRequest request) =>
            UserspaceFunc?.Invoke(request) ?? _defaultImpl.Userspace(request);

        /// <summary>
        /// Использовать данный экземпляр в качестве имплементации описания методов расширения пользовательских
        /// прав. Если установлен флаг AutoAssign, метод должен вызываться автоматически при переприсвоении функций-значений.
        /// </summary>
        public void Assign() => GrantsExtensions.Implementation = this;

        /// <summary>
        /// Вернуть реализацию методов расширений пользовательских прав по умолчанию.
        /// </summary>
        public void RevertToDefaults() => GrantsExtensions.Implementation = _defaultImpl;
    }
}
