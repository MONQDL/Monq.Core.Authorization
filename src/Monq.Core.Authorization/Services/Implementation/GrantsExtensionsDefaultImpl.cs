using Microsoft.AspNetCore.Http;
using Monq.Core.Authorization;
using Monq.Core.Authorization.Exceptions;
using Monq.Core.Authorization.Helpers;
using Monq.Core.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authorization;

internal class GrantsExtensionsDefaultImpl : IGrantsExtensions
{
    const sbyte SystemUserId = -1;
    const sbyte DefaultUserId = 0;

    const string SubjectClaim = "sub";
    const string ClientIdClaim = "client_id";
    const string ClientIdValue = "smon-res-owner";

    const string UserspaceIdHeader = "x-smon-userspace-id";

    /// <summary>
    /// Gets the user Id from the <see cref="ClaimsPrincipal"/>.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <returns>The user identifier, -1 for a system user, or 0 if it cannot be determined.</returns>
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
    /// Gets the user permission packets from the <see cref="ClaimsPrincipal"/>.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <returns>The collection of user permission packets <see cref="IEnumerable{PacketViewModel}"/>.</returns>
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
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has the grant specified by name.
    /// Always unconditionally returns <c>true</c> for a system user and a userspace administrator.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="workGroupId">The identifier of the work group in which the grant is checked.</param>
    /// <param name="grantName">The string representation of the grant (for example, "base-system.rsm.read").</param>
    /// <returns>True if the request user has the specified grant.</returns>
    public bool HasGrant(ClaimsPrincipal? user, long userspaceId, long workGroupId, string grantName)
        => HasAnyGrant(user, userspaceId, workGroupId, new[] { grantName });

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> has at least one of the specified grants.
    /// Always unconditionally returns <c>true</c> for a system user and a userspace administrator.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="workGroupId">The identifier of the work group in which the grants are checked.</param>
    /// <param name="grantNames">The string representations of the grants (for example, "base-system.rsm.read").</param>
    /// <returns>True if the request user has at least one of the specified grants.</returns>
    public bool HasAnyGrant(ClaimsPrincipal? user, long userspaceId, long workGroupId, IEnumerable<string> grantNames)
    {
        if (IsSystemUser(user))
            return true;

        if (user is null || !grantNames.Any())
            return false;

        var packets = user.Packets(userspaceId);

        // TODO: This check looks like it needs to be revisited.
        // Admin panel grant check.
        var adminPanelGrants = grantNames.Where(x => x.Contains(Modules.GrantType.AdminsGrantSuffix, StringComparison.Ordinal));
        if (adminPanelGrants?.Any() == true)
        {
            var hasAdminPanelPackets = HasAnyUserspaceAdminPanelGrant(user, userspaceId, adminPanelGrants);
            if (hasAdminPanelPackets) 
                return true;
        }

        if (!packets.Any())
            return false;

        var userHasAnyGrant = packets
            .Where(val => grantNames.Any(val.Grants.Contains))  // Filter packets that contain any of the grants.
            .SelectMany(val => val.Owners)                      // Get the owners of the remaining packets.
            .Any(val => val.WorkGroupId == workGroupId);        // And check whether one of them is the target work group.
        return userHasAnyGrant;
    }

    /// <inheritdoc />
    public bool HasAllGrants(ClaimsPrincipal? user, long userspaceId, long workGroupId, IEnumerable<string> grantNames)
    {
        if (IsSystemUser(user))
            return true;

        if (user is null || !grantNames.Any())
            return false;

        var packets = user.Packets(userspaceId);

        if (!packets.Any())
            return false;

        // Get the identifiers of the user packets that have grants
        // related to the target work group.
        var workGroupRelatedPackets = packets
            .SelectMany(val => val.Owners)
            .Where(val => val.WorkGroupId == workGroupId)
            .Select(val => val.PacketId)
            .ToList();

        // Get the unique grants in these packets.
        var workGroupRelatedGrants = packets
            .Where(val => workGroupRelatedPackets.Contains(val.Id))
            .SelectMany(val => val.Grants)
            .Distinct()
            .ToList();

        // Check all the requested grants in the resulting collection.
        var userHasAllGrants = grantNames.All(workGroupRelatedGrants.Contains);
        return userHasAllGrants;
    }

    /// <inheritdoc />
    public bool IsWorkGroupManager(ClaimsPrincipal? user, long userspaceId, long workGroupId)
    {
        if (user is null)
            return false;

        var packets = user.Packets(userspaceId);
        if (!packets.Any())
            return false;

        // Filter by the presence of the system WorkgroupManager packet for the user.
        return packets
            .Any(val => val.Owners
                .Any(owner => owner.WorkGroupId == workGroupId && owner.UserspaceId == userspaceId)
                && val.Type == PacketTypes.Manager);
    }

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
            .Where(val => grants.Any(val.Grants.Contains))  // Filter packets that contain any of the grants.
            .SelectMany(val => val.Owners)                      // Get the owners of the remaining packets.
            .Any(val => val.UserspaceId == userspaceId);        // And check whether the owner is in the userspace.
        return userHasAnyGrant;
    }

    /// <summary>
    /// Checks whether the user from the <see cref="ClaimsPrincipal"/> is a system user.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <returns>True if the user has system user credentials.</returns>
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
    /// Gets the Ids of the work groups in which the user from the <see cref="ClaimsPrincipal"/>
    /// has the grant specified by name.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="grantName">The string representation of the grant (for example, "base-system.rsm.read").</param>
    /// <returns>
    /// The list of work group identifiers in which the user has the specified grant.
    /// </returns>
    public IEnumerable<long> GetWorkGroupsWithGrant(ClaimsPrincipal? user, long userspaceId, string grantName)
        => GetWorkGroupsWithAnyGrant(user, userspaceId, new[] { grantName });

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
    /// Gets the Ids of the work groups in which the user from the <see cref="ClaimsPrincipal"/>
    /// has all of the specified grants.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <param name="grantNames">The string representations of the grants (for example, "base-system.rsm.read").</param>
    /// <returns>
    /// The list of work group identifiers in which the user has the specified grant.
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
    /// Gets the Ids of the work groups in which the user from the <see cref="ClaimsPrincipal"/>
    /// has any grants.
    /// </summary>
    /// <param name="user">The request user from the User property in ControllerBase.</param>
    /// <param name="userspaceId">The userspace identifier.</param>
    /// <returns>The list of work group identifiers in which the user has any grant.</returns>
    public IEnumerable<long> WorkGroups(ClaimsPrincipal? user, long userspaceId)
        => Packets(user, userspaceId)
            .SelectMany(val => val.Owners)
            .Select(val => val.WorkGroupId)
            .Distinct()
            .ToList();

    /// <summary>
    /// Gets the userspace Id from the headers of the executing <see cref="HttpRequest"/>.
    /// </summary>
    /// <param name="request">The request from the Request property in ControllerBase.</param>
    /// <returns>The userspace identifier, or 0 if it cannot be determined.</returns>
    public long Userspace(HttpRequest request)
    {
        // Get the first header key that matches the expected one in any casing,
        // or null if there are no such headers.
        var userspaceIdHeaderKey = request.Headers.Keys.FirstOrDefault(val =>
            string.Equals(val, UserspaceIdHeader, StringComparison.OrdinalIgnoreCase));

        if (string.IsNullOrWhiteSpace(userspaceIdHeaderKey))
        {
            throw new UserspaceNotFoundException($"Header {UserspaceIdHeader} not defined.");
        }

        // Get the value using the key matched with the correct casing.
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
