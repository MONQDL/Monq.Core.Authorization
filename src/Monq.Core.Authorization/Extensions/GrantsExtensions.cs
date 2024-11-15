﻿using Microsoft.AspNetCore.Http;
using Monq.Core.Authorization.Models;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authorization;

/// <summary>
/// Расширения для работы с идентификаторами на основе утверждений.
/// </summary>
public static class GrantsExtensions
{
    const string ObjectType = "objectType";
    const string ObjectId = "objectId";

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
    /// Get user packets from <see cref="ClaimsPrincipal"/>.
    /// </summary>
    /// <param name="user">User.</param>
    /// <param name="userspaceId">Identifier userspace.</param>
    /// <returns>Collection of user packets <see cref="IEnumerable{PacketViewModel}"/>.</returns>
    public static IEnumerable<PacketViewModel> Packets(this ClaimsPrincipal user, in long userspaceId)
        => Implementation.Packets(user, userspaceId);

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
    /// Проверить, является ли пользователь менеджером рабочей группы.
    /// </summary>
    /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
    /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
    /// <param name="workGroupId">Идентификатор рабочей группы, в которой проверяется наличие прав.</param>
    /// <returns>Истина, если пользователь является менеджером выбранной рабочей группы.</returns>
    public static bool IsWorkGroupManager(this ClaimsPrincipal user, long userspaceId, long workGroupId) =>
        Implementation.IsWorkGroupManager(user, userspaceId, workGroupId);

    /// <summary>
    /// Проверить, является ли пользователь с данным идентификатором <paramref name="userspaceId"/>
    /// из <see cref="ClaimsPrincipal"/> администратором пользовательского пространства 
    /// или обладает правом доступа к пользовательским сущностям.
    /// </summary>
    /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
    /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
    /// <returns>Истина, если пользователь -- администратор заданного пользовательского пространства или обладает правом доступа к пользовательским сущностям.</returns>
    public static bool IsUserspaceAdmin(this ClaimsPrincipal user, in long userspaceId)
        => Implementation.IsUserspaceAdmin(user, userspaceId);

    /// <summary>
    /// Проверить, есть ли у пользователя
    /// с данным идентификатором <paramref name="userspaceId"/>
    /// право доступа к пользовательским сущностям.
    /// </summary>
    /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
    /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
    /// <returns>Истина, если у пользователя есть право доступа к пользовательским сущностям.</returns>
    public static bool HasUsersEntitiesGrant(this ClaimsPrincipal user, in long userspaceId)
        => Implementation.HasUsersEntitiesGrant(user, userspaceId);

    /// <summary>
    /// Проверить есть ли у пользователя
    /// с данным идентификатором <paramref name="userspaceId"/>
    /// право из админ. панели.
    /// </summary>
    /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
    /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
    /// <param name="adminPanelGrant">Строковое представление права админ. панели (например, "pl.admins.user-entities-write").</param>
    /// <returns>Истина при наличии права.</returns>
    public static bool HasUserspaceAdminPanelGrant(this ClaimsPrincipal? user, long userspaceId, string adminPanelGrant)
        => Implementation.HasUserspaceAdminPanelGrant(user, userspaceId, adminPanelGrant);

    /// <summary>
    /// Проверить, есть ли хотя бы одно из заданных прав админ. панели у пользователя из <see cref="ClaimsPrincipal"/>.
    /// </summary>
    /// <param name="user">Пользователь запроса из свойства User в ControllerBase.</param>
    /// <param name="userspaceId">Идентификатор пользовательского пространства.</param>
    /// <param name="adminPanelGrantNames">Строковые представления прав админ панели (например, "pl.admins.user-entities-write").</param>
    /// <returns>Истина, если хотя бы одно заданное право есть у пользователя запроса.</returns>
    public static bool HasAnyUserspaceAdminPanelGrant(this ClaimsPrincipal user, long userspaceId,
        IEnumerable<string> adminPanelGrantNames)
        => Implementation.HasAnyUserspaceAdminPanelGrant(user, userspaceId, adminPanelGrantNames);

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
    /// <returns>Истина, если пользователь -- системный или администратор заданного пользовательского пространства.</returns>
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
    /// Получить Id пользовательского пространства из заголовков <see cref="HttpRequest"/> исполняемого запроса.
    /// </summary>
    /// <param name="request">Запрос из свойства Request в ControllerBase.</param>
    /// <returns>Идентификатор пользовательского пространства или 0, если неопределим.</returns>
    public static long Userspace(this HttpRequest request)
        => Implementation.Userspace(request);

    /// <summary>
    /// Generate a unique key for the service user.
    /// </summary>
    /// <param name="user">User.</param>
    /// <returns>Object key for service user or null.</returns>
    public static string? ObjectKey(this ClaimsPrincipal user)
    {
        var objectTypeClaim = user.Claims.FirstOrDefault(x => x.Type == ObjectType);
        var objectIdClaim = user.Claims.FirstOrDefault(x => x.Type == ObjectId);

        if (objectTypeClaim == null || objectIdClaim == null) return null;
        return $"{objectTypeClaim.Value}:{objectIdClaim.Value}";
    }
}
