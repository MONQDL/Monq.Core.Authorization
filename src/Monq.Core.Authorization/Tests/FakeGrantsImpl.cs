using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Monq.Core.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace Monq.Core.Authorization.Tests;

/// <summary>
/// Reference test implementation of the user grant extension methods for claim-based identifiers
/// (see <see cref="IGrantsExtensions"/>).
/// </summary>
public class FakeGrantsImpl : IGrantsExtensions
{
    readonly GrantsExtensionsDefaultImpl _defaultImpl
        = new GrantsExtensionsDefaultImpl();

    /// <summary>
    /// Gets the collection of user permission packets from the <see cref="ClaimsPrincipal"/>.
    /// </summary>
    public Func<ClaimsPrincipal?, IEnumerable<PacketViewModel>>? PacketsFunc { get; set; }

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has all of the specified grants.
    /// </summary>
    public Func<ClaimsPrincipal?, long, long, IEnumerable<string>, bool>? HasAllGrantsFunc { get; set; }

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has at least one of the specified grants.
    /// </summary>
    public Func<ClaimsPrincipal?, long, long, IEnumerable<string>, bool>? HasAnyGrantFunc { get; set; }

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has the grant specified by name.
    /// </summary>
    public Func<ClaimsPrincipal?, long, long, string, bool>? HasGrantFunc { get; set; }

    /// <summary>
    /// Checks whether the user is a work group manager.
    /// </summary>
    public Func<ClaimsPrincipal?, long, long, bool>? IsWorkGroupManagerFunc { get; set; }

    /// <summary>
    /// Gets the user Id from the <see cref="ClaimsPrincipal"/>.
    /// </summary>
    public Func<ClaimsPrincipal?, long>? SubjectFunc { get; set; }

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has access to user entities.
    /// </summary>
    public Func<ClaimsPrincipal?, long, bool>? HasUsersEntitiesGrantFunc { get; set; }

    /// <summary>
    /// Checks whether the user has an admin panel grant.
    /// </summary>
    public Func<ClaimsPrincipal?, long, string, bool>? HasUserspaceAdminPanelGrantFunc { get; set; }

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has at least one of the specified admin panel grants.
    /// </summary>
    public Func<ClaimsPrincipal?, long, IEnumerable<string>, bool>? HasAnyUserspaceAdminPanelGrantFunc { get; set; }

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> is a system user.
    /// </summary>
    public Func<ClaimsPrincipal?, bool>? IsSystemUserFunc { get; set; }

    /// <summary>
    /// Gets the Ids of the work groups in which the user from the <see cref="ClaimsPrincipal"/>
    /// has the grant specified by name.
    /// </summary>
    public Func<ClaimsPrincipal?, long, string, IEnumerable<long>>? GetWorkGroupsWithGrantFunc { get; set; }

    /// <summary>
    /// Gets the Ids of the work groups in which the user from the <see cref="ClaimsPrincipal"/>
    /// has at least one of the specified grants.
    /// </summary>
    public Func<ClaimsPrincipal?, long, IEnumerable<string>, IEnumerable<long>>? GetWorkGroupsWithAnyGrantFunc { get; set; }

    /// <summary>
    /// Gets the Ids of the work groups in which the user from the <see cref="ClaimsPrincipal"/>
    /// has all of the specified grants.
    /// </summary>
    public Func<ClaimsPrincipal?, long, IEnumerable<string>, IEnumerable<long>>? GetWorkGroupsWithAllGrantsFunc { get; set; }

    /// <summary>
    /// Gets the Ids of the work groups in which the user from the <see cref="ClaimsPrincipal"/>
    /// has any grants.
    /// </summary>
    public Func<ClaimsPrincipal?, long, IEnumerable<long>>? WorkGroupsFunc { get; set; }

    /// <summary>
    /// Gets the Ids of the userspaces in which the user from the <see cref="ClaimsPrincipal"/>
    /// has any grants.
    /// </summary>
    public Func<ClaimsPrincipal?, IEnumerable<long>>? UserspacesFunc { get; set; }

    /// <summary>
    /// Gets the userspace Id from the headers of the executing <see cref="HttpRequest"/>.
    /// </summary>
    public Func<HttpRequest, long>? UserspaceFunc { get; set; }

    /// <inheritdoc />
    public IEnumerable<PacketViewModel> Packets(ClaimsPrincipal? user, long userspaceId) =>
        PacketsFunc?.Invoke(user) ?? _defaultImpl.Packets(user, userspaceId);

    /// <inheritdoc />
    public bool HasAllGrants(ClaimsPrincipal? user, long userspaceId, long workGroupId, IEnumerable<string> grantNames) =>
        HasAllGrantsFunc?.Invoke(user, userspaceId, workGroupId, grantNames) ?? _defaultImpl.HasAllGrants(user, userspaceId, workGroupId, grantNames);

    /// <inheritdoc />
    public bool HasAnyGrant(ClaimsPrincipal? user, long userspaceId, long workGroupId, IEnumerable<string> grantNames) =>
        HasAnyGrantFunc?.Invoke(user, userspaceId, workGroupId, grantNames) ?? _defaultImpl.HasAnyGrant(user, userspaceId, workGroupId, grantNames);

    /// <inheritdoc />
    public bool HasGrant(ClaimsPrincipal? user, long userspaceId, long workGroupId, string grantName) =>
        HasGrantFunc?.Invoke(user, userspaceId, workGroupId, grantName) ?? _defaultImpl.HasGrant(user, userspaceId, workGroupId, grantName);

    /// <inheritdoc />
    public bool IsWorkGroupManager(ClaimsPrincipal? user, long userspaceId, long workGroupId) =>
        IsWorkGroupManagerFunc?.Invoke(user, userspaceId, workGroupId) ?? _defaultImpl.IsWorkGroupManager(user, userspaceId, workGroupId);

    /// <inheritdoc />
    public bool HasUserspaceAdminPanelGrant(ClaimsPrincipal? user, long userspaceId, string adminPanelGrant) =>
        HasUserspaceAdminPanelGrantFunc?.Invoke(user, userspaceId, adminPanelGrant) ??
        _defaultImpl.HasUserspaceAdminPanelGrant(user, userspaceId, adminPanelGrant);

    /// <inheritdoc />
    public bool HasAnyUserspaceAdminPanelGrant(ClaimsPrincipal? user, long userspaceId, IEnumerable<string> adminPanelGrants) =>
        HasAnyUserspaceAdminPanelGrantFunc?.Invoke(user, userspaceId, adminPanelGrants) ??
        _defaultImpl.HasAnyUserspaceAdminPanelGrant(user, userspaceId, adminPanelGrants);

    /// <inheritdoc />
    public long Subject(ClaimsPrincipal? user) =>
        SubjectFunc?.Invoke(user) ?? _defaultImpl.Subject(user);

    /// <inheritdoc />
    public bool IsSystemUser(ClaimsPrincipal? user) =>
        IsSystemUserFunc?.Invoke(user) ?? _defaultImpl.IsSystemUser(user);

    /// <inheritdoc />
    public IEnumerable<long> GetWorkGroupsWithGrant(ClaimsPrincipal? user, long userspaceId, string grantName) =>
        GetWorkGroupsWithGrantFunc?.Invoke(user, userspaceId, grantName) ?? _defaultImpl.GetWorkGroupsWithGrant(user, userspaceId, grantName);

    /// <inheritdoc />
    public IEnumerable<long> GetWorkGroupsWithAnyGrant(ClaimsPrincipal? user, long userspaceId, IEnumerable<string> grantNames) =>
        GetWorkGroupsWithAnyGrantFunc?.Invoke(user, userspaceId, grantNames) ?? _defaultImpl.GetWorkGroupsWithAnyGrant(user, userspaceId, grantNames);

    /// <inheritdoc />
    public IEnumerable<long> GetWorkGroupsWithAllGrants(ClaimsPrincipal? user, long userspaceId, IEnumerable<string> grantNames) =>
        GetWorkGroupsWithAllGrantsFunc?.Invoke(user, userspaceId, grantNames) ?? _defaultImpl.GetWorkGroupsWithAllGrants(user, userspaceId, grantNames);

    /// <inheritdoc />
    public IEnumerable<long> WorkGroups(ClaimsPrincipal? user, long userspaceId) =>
        WorkGroupsFunc?.Invoke(user, userspaceId) ?? _defaultImpl.WorkGroups(user, userspaceId);

    /// <inheritdoc />
    public long Userspace(HttpRequest request) =>
        UserspaceFunc?.Invoke(request) ?? _defaultImpl.Userspace(request);

    /// <summary>
    /// Uses this instance as the implementation of the user grant extension methods.
    /// If the AutoAssign flag is set, this method should be called automatically when value functions are reassigned.
    /// </summary>
    public void Assign() => GrantsExtensions.Implementation = this;

    /// <summary>
    /// Restores the default implementation of the user grant extension methods.
    /// </summary>
    public void RevertToDefaults() => GrantsExtensions.Implementation = _defaultImpl;
}
