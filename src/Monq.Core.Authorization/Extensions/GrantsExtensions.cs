using Microsoft.AspNetCore.Http;
using Monq.Core.Authorization.Models;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authorization;

/// <summary>
/// Extensions for working with claim-based identifiers.
/// </summary>
public static class GrantsExtensions
{
    const string ObjectType = "objectType";
    const string ObjectId = "objectId";

    /// <summary>
    /// The implementation of the user grant extension methods.
    /// </summary>
    public static IGrantsExtensions Implementation { get; set; }
        = new GrantsExtensionsDefaultImpl();

    /// <summary>
    /// Gets the user Id from the <see cref="ClaimsPrincipal"/>.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <returns>The user identifier, -1 for a system user, or 0 if it cannot be determined.</returns>
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
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has the grant specified by name.
    /// Always unconditionally returns <c>true</c> for a system user and a userspace administrator.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="workGroupId">The identifier of the work group in which the grant is checked.</param>
    /// <param name="grantName">The string representation of the grant (for example, "base-system.rsm.read").</param>
    /// <returns>True if the request user has the specified grant.</returns>
    public static bool HasGrant(this ClaimsPrincipal user, in long userspaceId, in long workGroupId, in string grantName)
        => Implementation.HasGrant(user, userspaceId, workGroupId, grantName);

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has at least one of the specified grants.
    /// Always unconditionally returns <c>true</c> for a system user and a userspace administrator.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="workGroupId">The identifier of the work group in which the grants are checked.</param>
    /// <param name="grantNames">The string representations of the grants (for example, "base-system.rsm.read").</param>
    /// <returns>True if the request user has at least one of the specified grants.</returns>
    public static bool HasAnyGrant(this ClaimsPrincipal user, in long userspaceId, in long workGroupId, in IEnumerable<string> grantNames)
        => Implementation.HasAnyGrant(user, userspaceId, workGroupId, grantNames);

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has all of the specified grants.
    /// Always unconditionally returns <c>true</c> for a system user and a userspace administrator.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="workGroupId">The identifier of the work group in which the grants are checked.</param>
    /// <param name="grantNames">The string representations of the grants (for example, "base-system.rsm.read").</param>
    /// <returns>True if the request user has all of the specified grants.</returns>
    public static bool HasAllGrants(this ClaimsPrincipal user, in long userspaceId, in long workGroupId, in IEnumerable<string> grantNames)
        => Implementation.HasAllGrants(user, userspaceId, workGroupId, grantNames);

    /// <summary>
    /// Checks whether the user is a work group manager.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="workGroupId">The identifier of the work group in which the role is checked.</param>
    /// <returns>True if the user is a manager of the selected work group.</returns>
    public static bool IsWorkGroupManager(this ClaimsPrincipal user, long userspaceId, long workGroupId) =>
        Implementation.IsWorkGroupManager(user, userspaceId, workGroupId);

    /// <summary>
    /// Checks whether the user with the given <paramref name="userspaceId"/> has an admin panel grant.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="adminPanelGrant">The string representation of the admin panel grant (for example, "pl.admins.user-entities-write").</param>
    /// <returns>True if the grant is present.</returns>
    public static bool HasUserspaceAdminPanelGrant(this ClaimsPrincipal user, long userspaceId, string adminPanelGrant)
        => Implementation.HasUserspaceAdminPanelGrant(user, userspaceId, adminPanelGrant);

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has at least one of the specified admin panel grants.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="adminPanelGrantNames">The string representations of the admin panel grants (for example, "pl.admins.user-entities-write").</param>
    /// <returns>True if the request user has at least one of the specified grants.</returns>
    public static bool HasAnyUserspaceAdminPanelGrant(this ClaimsPrincipal user, long userspaceId,
        IEnumerable<string> adminPanelGrantNames)
        => Implementation.HasAnyUserspaceAdminPanelGrant(user, userspaceId, adminPanelGrantNames);

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> is a system user.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <returns>True if the user has system user credentials.</returns>
    public static bool IsSystemUser(this ClaimsPrincipal user)
        => Implementation.IsSystemUser(user);

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
    public static IEnumerable<long> GetWorkGroupsWithGrant(this ClaimsPrincipal user, in long userspaceId, in string grantName)
        => Implementation.GetWorkGroupsWithGrant(user, userspaceId, grantName);

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
    public static IEnumerable<long> GetWorkGroupsWithAnyGrant(this ClaimsPrincipal user, in long userspaceId, in IEnumerable<string> grantNames)
        => Implementation.GetWorkGroupsWithAnyGrant(user, userspaceId, grantNames);

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
    public static IEnumerable<long> GetWorkGroupsWithAllGrants(this ClaimsPrincipal user, in long userspaceId, in IEnumerable<string> grantNames)
        => Implementation.GetWorkGroupsWithAllGrants(user, userspaceId, grantNames);

    /// <summary>
    /// Gets the Ids of the work groups in which the user from the <see cref="ClaimsPrincipal"/>
    /// has any grants.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <returns>
    /// The list of work group identifiers in which the user has any grant.
    /// </returns>
    public static IEnumerable<long> WorkGroups(this ClaimsPrincipal user, in long userspaceId)
        => Implementation.WorkGroups(user, userspaceId);

    /// <summary>
    /// Gets the userspace Id from the headers of the executing <see cref="HttpRequest"/>.
    /// </summary>
    /// <param name="request">The request from the Request property in ControllerBase.</param>
    /// <returns>The userspace identifier, or 0 if it cannot be determined.</returns>
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

        if (objectTypeClaim == null || objectIdClaim == null) 
            return null;

        return $"{objectTypeClaim.Value}:{objectIdClaim.Value}";
    }
}
