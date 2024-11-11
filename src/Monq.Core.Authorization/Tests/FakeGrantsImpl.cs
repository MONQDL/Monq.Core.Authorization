using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Monq.Core.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace Monq.Core.Authorization.Tests;

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
    /// Проверить, является ли пользователь менеджером рабочей группы.
    /// </summary>
    public Func<ClaimsPrincipal, long, long, bool>? IsWorkGroupManagerFunc { get; set; }

    /// <summary>
    /// Получить Id пользователя из <see cref="ClaimsPrincipal"/>.
    /// </summary>
    public Func<ClaimsPrincipal, long>? SubjectFunc { get; set; }

    /// <summary>
    /// Проверить, является ли пользователь из <see cref="ClaimsPrincipal"/>
    /// администратором пользовательского пространства с данным идентификатором.
    /// </summary>
    public Func<ClaimsPrincipal, long, bool>? IsUserspaceAdminFunc { get; set; }

    /// <summary>
    /// Проверить, есть ли у пользователь
    /// из <see cref="ClaimsPrincipal"/> доступ к пользовательским сущностям.
    /// </summary>
    public Func<ClaimsPrincipal, long, bool>? HasUsersEntitiesGrantFunc { get; set; }

    /// <summary>
    /// Проверить есть ли у пользователя
    /// право из админ. панели.
    /// </summary>
    public Func<ClaimsPrincipal, long, string, bool>? HasUserspaceAdminPanelGrantFunc { get; set; }

    /// <summary>
    /// Проверить, есть ли хотя бы одно из заданных прав админ. панели у пользователя из <see cref="ClaimsPrincipal"/>.
    /// </summary>
    public Func<ClaimsPrincipal, long, IEnumerable<string>, bool>? HasAnyUserspaceAdminPanelGrantFunc { get; set; }

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

    /// <inheritdoc />
    public IEnumerable<PacketViewModel> Packets(ClaimsPrincipal user, long userspaceId) =>
        PacketsFunc?.Invoke(user) ?? _defaultImpl.Packets(user, userspaceId);

    /// <inheritdoc />
    public bool HasAllGrants(ClaimsPrincipal user, long userspaceId, long workGroupId, IEnumerable<string> grantNames) =>
        HasAllGrantsFunc?.Invoke(user, userspaceId, workGroupId, grantNames) ?? _defaultImpl.HasAllGrants(user, userspaceId, workGroupId, grantNames);

    /// <inheritdoc />
    public bool HasAnyGrant(ClaimsPrincipal user, long userspaceId, long workGroupId, IEnumerable<string> grantNames) =>
        HasAnyGrantFunc?.Invoke(user, userspaceId, workGroupId, grantNames) ?? _defaultImpl.HasAnyGrant(user, userspaceId, workGroupId, grantNames);

    /// <inheritdoc />
    public bool HasGrant(ClaimsPrincipal user, long userspaceId, long workGroupId, string grantName) =>
        HasGrantFunc?.Invoke(user, userspaceId, workGroupId, grantName) ?? _defaultImpl.HasGrant(user, userspaceId, workGroupId, grantName);

    /// <inheritdoc />
    public bool IsWorkGroupManager(ClaimsPrincipal user, long userspaceId, long workGroupId) =>
        IsWorkGroupManagerFunc?.Invoke(user, userspaceId, workGroupId) ?? _defaultImpl.IsWorkGroupManager(user, userspaceId, workGroupId);

    /// <inheritdoc />
    public bool IsUserspaceAdmin(ClaimsPrincipal user, long userspaceId) =>
        IsUserspaceAdminFunc?.Invoke(user, userspaceId) ?? _defaultImpl.IsUserspaceAdmin(user, userspaceId);

    /// <inheritdoc />
    public bool HasUsersEntitiesGrant(ClaimsPrincipal user, long userspaceId) =>
        HasUsersEntitiesGrantFunc?.Invoke(user, userspaceId) ?? _defaultImpl.HasUsersEntitiesGrant(user, userspaceId);

    /// <inheritdoc />
    public bool HasUserspaceAdminPanelGrant(ClaimsPrincipal? user, long userspaceId, string adminPanelGrant) =>
        HasUserspaceAdminPanelGrantFunc?.Invoke(user, userspaceId, adminPanelGrant) ??
        _defaultImpl.HasUserspaceAdminPanelGrant(user, userspaceId, adminPanelGrant);

    /// <inheritdoc />
    public bool HasAnyUserspaceAdminPanelGrant(ClaimsPrincipal? user, long userspaceId, IEnumerable<string> adminPanelGrants) =>
        HasAnyUserspaceAdminPanelGrantFunc?.Invoke(user, userspaceId, adminPanelGrants) ??
        _defaultImpl.HasAnyUserspaceAdminPanelGrant(user, userspaceId, adminPanelGrants);

    /// <inheritdoc />
    public long Subject(ClaimsPrincipal user) =>
        SubjectFunc?.Invoke(user) ?? _defaultImpl.Subject(user);

    /// <inheritdoc />
    public bool IsSuperUser(ClaimsPrincipal user, long userspaceId) =>
        IsSuperUserFunc?.Invoke(user, userspaceId) ?? _defaultImpl.IsSuperUser(user, userspaceId);

    /// <inheritdoc />
    public bool IsSystemUser(ClaimsPrincipal user) =>
        IsSystemUserFunc?.Invoke(user) ?? _defaultImpl.IsSystemUser(user);

    /// <inheritdoc />
    public IEnumerable<long> GetWorkGroupsWithGrant(ClaimsPrincipal user, long userspaceId, string grantName) =>
        GetWorkGroupsWithGrantFunc?.Invoke(user, userspaceId, grantName) ?? _defaultImpl.GetWorkGroupsWithGrant(user, userspaceId, grantName);

    /// <inheritdoc />
    public IEnumerable<long> GetWorkGroupsWithAnyGrant(ClaimsPrincipal user, long userspaceId, IEnumerable<string> grantNames) =>
        GetWorkGroupsWithAnyGrantFunc?.Invoke(user, userspaceId, grantNames) ?? _defaultImpl.GetWorkGroupsWithAnyGrant(user, userspaceId, grantNames);

    /// <inheritdoc />
    public IEnumerable<long> GetWorkGroupsWithAllGrants(ClaimsPrincipal user, long userspaceId, IEnumerable<string> grantNames) =>
        GetWorkGroupsWithAllGrantsFunc?.Invoke(user, userspaceId, grantNames) ?? _defaultImpl.GetWorkGroupsWithAllGrants(user, userspaceId, grantNames);

    /// <inheritdoc />
    public IEnumerable<long> WorkGroups(ClaimsPrincipal user, long userspaceId) =>
        WorkGroupsFunc?.Invoke(user, userspaceId) ?? _defaultImpl.WorkGroups(user, userspaceId);

    /// <inheritdoc />
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
