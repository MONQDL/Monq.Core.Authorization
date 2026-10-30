using Microsoft.AspNetCore.Http;
using Monq.Core.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authorization;

/// <summary>
/// Describes user grant extension methods for claim-based identifiers (see <see cref="ClaimsPrincipal"/>).
/// </summary>
public interface IGrantsExtensions
{
    /// <summary>
    /// Gets the user Id from the <see cref="ClaimsPrincipal"/>.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <returns>The user identifier, -1 for a system user, or 0 if it cannot be determined.</returns>
    long Subject(ClaimsPrincipal? user);

    /// <summary>
    /// Gets the user permission packets from the <see cref="ClaimsPrincipal"/>.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <returns>The collection of user permission packets <see cref="IEnumerable{PacketViewModel}"/>.</returns>
    IEnumerable<PacketViewModel> Packets(ClaimsPrincipal? user, long userspaceId);

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has the grant specified by name.
    /// Always unconditionally returns <c>true</c> for a system user and a userspace administrator.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="workGroupId">The identifier of the work group in which the grant is checked.</param>
    /// <param name="grantName">The string representation of the grant (for example, "base-system.rsm.read").</param>
    /// <returns>True if the request user has the specified grant.</returns>
    bool HasGrant(ClaimsPrincipal? user, long userspaceId, long workGroupId, string grantName);

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has at least one of the specified grants.
    /// Always unconditionally returns <c>true</c> for a system user and a userspace administrator.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="workGroupId">The identifier of the work group in which the grants are checked.</param>
    /// <param name="grantNames">The string representations of the grants (for example, "base-system.rsm.read").</param>
    /// <returns>True if the request user has at least one of the specified grants.</returns>
    bool HasAnyGrant(ClaimsPrincipal? user, long userspaceId, long workGroupId, IEnumerable<string> grantNames);

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has all of the specified grants.
    /// Always unconditionally returns <c>true</c> for a system user and a userspace administrator.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="workGroupId">The identifier of the work group in which the grants are checked.</param>
    /// <param name="grantNames">The string representations of the grants (for example, "base-system.rsm.read").</param>
    /// <returns>True if the request user has all of the specified grants.</returns>
    bool HasAllGrants(ClaimsPrincipal? user, long userspaceId, long workGroupId, IEnumerable<string> grantNames);

    /// <summary>
    /// Checks whether the user is a work group manager.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="workGroupId">The identifier of the work group in which the role is checked.</param>
    /// <returns>True if the user is a manager of the selected work group.</returns>
    bool IsWorkGroupManager(ClaimsPrincipal? user, long userspaceId, long workGroupId);

    /// <summary>
    /// Checks whether the user with the given <paramref name="userspaceId"/> has an admin panel grant.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="adminPanelGrant">The string representation of the admin panel grant (for example, "pl.admins.user-entities-write").</param>
    /// <returns>True if the grant is present.</returns>
    bool HasUserspaceAdminPanelGrant(ClaimsPrincipal? user, long userspaceId, string adminPanelGrant);

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has at least one of the specified admin panel grants.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="adminPanelGrantNames">The string representations of the admin panel grants (for example, "pl.admins.user-entities-write").</param>
    /// <returns>True if the request user has at least one of the specified grants.</returns>
    bool HasAnyUserspaceAdminPanelGrant(ClaimsPrincipal? user, long userspaceId,
        IEnumerable<string> adminPanelGrantNames);

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> is a system user.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <returns>True if the user has system user privileges.</returns>
    bool IsSystemUser(ClaimsPrincipal? user);

    /// <summary>
    /// Gets the Ids of the work groups in which the user from the <see cref="ClaimsPrincipal"/>
    /// has the grant specified by name.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="grantName">The string representation of the grant (for example, "base-system.rsm.read").</param>
    /// <returns>
    /// The list of work group identifiers in which the user has the specified grant.
    /// </returns>
    IEnumerable<long> GetWorkGroupsWithGrant(ClaimsPrincipal? user, long userspaceId, string grantName);

    /// <summary>
    /// Gets the Ids of the work groups in which the user from the <see cref="ClaimsPrincipal"/>
    /// has at least one of the specified grants.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="grantNames">The string representations of the grants (for example, "base-system.rsm.read").</param>
    /// <returns>
    /// The list of work group identifiers in which the user has the specified grant.
    /// </returns>
    IEnumerable<long> GetWorkGroupsWithAnyGrant(ClaimsPrincipal? user, long userspaceId, IEnumerable<string> grantNames);

    /// <summary>
    /// Gets the Ids of the work groups in which the user from the <see cref="ClaimsPrincipal"/>
    /// has all of the specified grants.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="grantNames">The string representations of the grants (for example, "base-system.rsm.read").</param>
    /// <returns>
    /// The list of work group identifiers in which the user has the specified grant.
    /// </returns>
    IEnumerable<long> GetWorkGroupsWithAllGrants(ClaimsPrincipal? user, long userspaceId, IEnumerable<string> grantNames);

    /// <summary>
    /// Gets the Ids of the work groups in which the user from the <see cref="ClaimsPrincipal"/>
    /// has any grants.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <returns>
    /// The list of work group identifiers in which the user has any grant.
    /// </returns>
    IEnumerable<long> WorkGroups(ClaimsPrincipal? user, long userspaceId);

    /// <summary>
    /// Gets the userspace Id from the headers of the executing <see cref="HttpRequest"/>.
    /// </summary>
    /// <param name="request">The request from the Request property in ControllerBase.</param>
    /// <returns>The userspace identifier, or 0 if it cannot be determined.</returns>
    long Userspace(HttpRequest request);
}
