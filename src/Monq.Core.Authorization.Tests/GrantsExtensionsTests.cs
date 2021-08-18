using IdentityModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Monq.Core.Authorization.Exceptions;
using Monq.Core.Authorization.Helpers;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Monq.Core.Authorization.Models;
using Xunit;

namespace Monq.Core.Authorization.Tests
{
#pragma warning disable RCS1123 // Add parentheses according to operator precedence.
#pragma warning disable CA1822 // Mark members as static
    public class GrantsExtensionsTests
    {
        const sbyte _userspaceAdminPacketId = 1;

        [Fact(DisplayName = "GrantsExtensions: Subject(): Проверка возврата идентификатора системного пользователя при отсутствии user.")]
        public void ShouldProperlyReturnSystemUserIdForNullClaimPrincipal()
        {
            const int systemUserId = -1;
            var claim = TestData.CreateSystemUserClaimPrincipal();

            var subj = claim.Subject();
            Assert.Equal(systemUserId, subj);
        }

        [Theory(DisplayName = "GrantsExtensions: Subject(): Проверка возврата корректного значения пользовательского идентификатора.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyReturnValueForCorrectPrincipal(int seed)
        {
            var sporadic = new Random(seed);
            var id = sporadic.GetId();
            var claim = TestData.CreateUserClaimPrincipal(id);

            var subj = claim.Subject();
            Assert.Equal(id, subj);
        }

        [Fact(DisplayName = "GrantsExtensions: Subject(): Проверка возврата 0 при отсутствии пользовательского идентификатора.")]
        public void ShouldProperlyReturnDefaultValueForMissingPrincipal()
        {
            const int expectedResult = 0;

            var ci = new ClaimsIdentity(Array.Empty<Claim>());
            var claim = new ClaimsPrincipal(ci);

            var subj = claim.Subject();
            Assert.Equal(expectedResult, subj);
        }

        [Fact(DisplayName = "GrantsExtensions: Subject(): Проверка возврата 0 при отсутствии пользовательского идентификатора.")]
        public void ShouldProperlyReturnDefaultValueFoNullPrincipal()
        {
            const int expectedResult = 0;

            ClaimsPrincipal claim = null;

            var subj = claim.Subject();
            Assert.Equal(expectedResult, subj);
        }

        [Fact(DisplayName = "GrantsExtensions: Subject(): Проверка возврата 0 при некорректном пользовательском идентификаторе.")]
        public void ShouldProperlyReturnDefaultValueForIncorrectPrincipal()
        {
            const string id = "test";
            const int expectedResult = 0;

            var claims = new Claim[] { new Claim(JwtClaimTypes.Subject, id) };
            var ci = new ClaimsIdentity(claims);
            var claim = new ClaimsPrincipal(ci);

            var subj = claim.Subject();
            Assert.Equal(expectedResult, subj);
        }

        [Theory(DisplayName = "GrantsExtensions: Packets(): Проверка возврата корректного значения при корректном запросе.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyReturnExistingPackets(int seed)
        {
            var sporadic = new Random(seed);
            var packetId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var userId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var packetToSet = TestData.CreatePacket(packetId, userspaceId, workGroupId, userId);

            PacketRepository.Set(userId, packetToSet);

            var claim = TestData.CreateUserClaimPrincipal(userId);
            var packets = claim.Packets();
            Assert.NotEmpty(packets);
            Assert.Single(packets);

            var packet = packets.First();
            Assert.Equal(packetId, packet.Id);

            var owner = packet.Owners.First();
            Assert.Equal(workGroupId, owner.WorkGroupId);
            Assert.Contains(userId, owner.Users);
        }

        [Theory(DisplayName = "GrantsExtensions: Packets(): Проверка возврата пустого списка для некорректного значения.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyReturnEmptyValueForInappropriateSubject(int seed)
        {
            var sporadic = new Random(seed);
            var packetId = sporadic.GetId();
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            const int subjectId = -1;

            var packetToSet = TestData.CreatePacket(packetId, userspaceId, workGroupId, userId);

            PacketRepository.Set(userId, packetToSet);
            var incorrentClaim = TestData.CreateUserClaimPrincipal(subjectId);

            var incorrentGrants = incorrentClaim.Packets();
            Assert.Empty(incorrentGrants);
        }

        [Theory(DisplayName = "GrantsExtensions: HasGrant(): Проверка истина при корректном запросе.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyReturnTrueIfUserHasGrant(int seed)
        {
            var sporadic = new Random(seed);
            var packetId = sporadic.GetId();
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var packetToSet = TestData.CreatePacket(packetId, userspaceId, workGroupId, userId);

            PacketRepository.Set(userId, packetToSet);
            var claim = TestData.CreateUserClaimPrincipal(userId);

            var hasGrant = claim.HasGrant(userspaceId, workGroupId, packetToSet.Grants.First());
            Assert.True(hasGrant);
        }

        [Theory(DisplayName = "GrantsExtensions: HasGrant(): Проверка ложь при пустом запросе.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnFalseForEmptyGrantNameOnHasGrantRequest(int seed)
        {
            var sporadic = new Random(seed);
            var packetId = sporadic.GetId();
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var packetToSet = TestData.CreatePacket(packetId, userspaceId, workGroupId, userId);

            PacketRepository.Set(userId, packetToSet);
            var claim = TestData.CreateUserClaimPrincipal(userId);

            var hasGrant = claim.HasGrant(userspaceId, workGroupId, string.Empty);
            Assert.False(hasGrant);
        }

        [Theory(DisplayName = "GrantsExtensions: HasGrant(): Проверка ложь при некорректном запросе.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnFalseIfUserHasntGrant(int seed)
        {
            var sporadic = new Random(seed);
            var packetId = sporadic.GetId();
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var packetToSet = TestData.CreatePacket(packetId, userspaceId, workGroupId, userId);

            PacketRepository.Set(userId, packetToSet);
            var claim = TestData.CreateUserClaimPrincipal(userId);

            var grantName = sporadic.GetRandomModuleName();
            var hasGrant = claim.HasGrant(userspaceId, workGroupId, grantName);
            Assert.False(hasGrant);
        }

        [Theory(DisplayName = "GrantsExtensions: HasGrant(): Проверка ложь при ошибке рабочей группы.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnFalseIfUserHasntGrantInWorkGroup(int seed)
        {
            var sporadic = new Random(seed);
            var packetId = sporadic.GetId();
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var falseWorkGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var packetToSet = TestData.CreatePacket(packetId, userspaceId, workGroupId, userId);

            PacketRepository.Set(userId, packetToSet);
            var claim = TestData.CreateUserClaimPrincipal(userId);

            var hasGrant = claim.HasGrant(userspaceId, falseWorkGroupId, Modules.GrantType.BaseSystemWorkGroupRolesRead);
            Assert.False(hasGrant);
        }

        [Theory(DisplayName = "GrantsExtensions: HasGrant(): Проверка истина системному пользователю даже при ошибке рабочей группы.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnTrueForSystemUserOnHasGrantRequest(int seed)
        {
            var sporadic = new Random(seed);
            var packetId = sporadic.GetId();
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var falseWorkGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var packetToSet = TestData.CreatePacket(packetId, userspaceId, workGroupId, userId);
            PacketRepository.Set(userId, packetToSet);

            var claim = TestData.CreateSystemUserClaimPrincipal();

            var hasGrant = claim.HasGrant(userspaceId, falseWorkGroupId, Modules.GrantType.BaseSystemWorkGroupRolesRead);
            Assert.True(hasGrant);
        }

        [Theory(DisplayName = "GrantsExtensions: HasGrant(): Проверка истина администратору пространства даже при ошибке рабочей группы.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnTrueForUserspaceAdminOnHasGrantRequest(int seed)
        {
            var sporadic = new Random(seed);
            var packetId = sporadic.GetId();
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var falseWorkGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var packetToSet = TestData.CreatePacket(packetId, userspaceId, workGroupId, userId);
            PacketRepository.Set(userId, packetToSet);

            var requestUserId = sporadic.GetId();

            var systemPacketMaps = TestData.CreateSystemPacketMaps(_userspaceAdminPacketId, userspaceId);
            PacketRepository.SetSystemPacketMaps(requestUserId, systemPacketMaps);

            var adminPacket = TestData.CreatePacketUserspaceAdmin(_userspaceAdminPacketId, userspaceId, workGroupId, requestUserId);
            PacketRepository.Set(requestUserId, new[] { adminPacket });

            var claim = TestData.CreateUserClaimPrincipal(requestUserId);

            var hasGrant = claim.HasGrant(userspaceId, falseWorkGroupId, Modules.GrantType.BaseSystemWorkGroupRolesRead);
            Assert.True(hasGrant);
        }

        [Theory(DisplayName = "GrantsExtensions: HasAnyGrant(): Проверка истина при корректном запросе.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyReturnTrueIfUserHasAnyGrant(int seed)
        {
            var sporadic = new Random(seed);
            var packetId1 = sporadic.GetId();
            var packetId2 = sporadic.GetId();
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var packetToSet = TestData.CreatePacketWithRandomGrant(sporadic, packetId1, userspaceId, workGroupId, userId);

            PacketRepository.Set(userId, packetToSet);
            var claim = TestData.CreateUserClaimPrincipal(userId);

            var additionalPacketToRequest = TestData.CreatePacketWithRandomGrant(sporadic, packetId2, userspaceId, workGroupId, userId);
            var hasAnyGrant = claim.HasAnyGrant(userspaceId, workGroupId, new[] { packetToSet.Grants.First(), additionalPacketToRequest.Grants.First() });
            Assert.True(hasAnyGrant);
        }

        [Theory(DisplayName = "GrantsExtensions: HasAnyGrant(): Проверка ложь при некорректном запросе.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnFalseIfUserHasNoAppropriateGrantsOnHasAnyGrant(int seed)
        {
            var sporadic = new Random(seed);
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var claim = TestData.CreateUserClaimPrincipal(userId);
            var grantNameToRequest = sporadic.GetRandomGrantName();

            var hasAnyGrant = claim.HasAnyGrant(userspaceId, workGroupId, new[] { grantNameToRequest });
            Assert.False(hasAnyGrant);
        }

        [Theory(DisplayName = "GrantsExtensions: HasAnyGrant(): Проверка истина для системного пользователя.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnTrueForSystemUserOnHasAnyGrantRequest(int seed)
        {
            var sporadic = new Random(seed);
            var packetId = sporadic.GetId();
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var claim = TestData.CreateSystemUserClaimPrincipal();
            var grantToRequest = TestData.CreatePacketWithRandomGrant(sporadic, packetId, userspaceId, workGroupId, userId);
            var hasAnyGrant = claim.HasAnyGrant(userspaceId, workGroupId, new[] { grantToRequest.Grants.First() });
            Assert.True(hasAnyGrant);
        }

        [Theory(DisplayName = "GrantsExtensions: HasAnyGrant(): Проверка истина администратору пространства даже при ошибке рабочей группы.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnTrueForUserspaceAdminOnHasAnyGrantRequest(int seed)
        {
            var sporadic = new Random(seed);
            var packetId = sporadic.GetId();
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var falseWorkGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var packetToSet = TestData.CreatePacket(packetId, userspaceId, workGroupId, userId);
            PacketRepository.Set(userId, packetToSet);

            var requestUserId = sporadic.GetId();

            var systemPacketMaps = TestData.CreateSystemPacketMaps(_userspaceAdminPacketId, userspaceId);
            PacketRepository.SetSystemPacketMaps(requestUserId, systemPacketMaps);

            var adminPacket = TestData.CreatePacketUserspaceAdmin(_userspaceAdminPacketId, userspaceId, workGroupId, requestUserId);
            PacketRepository.Set(requestUserId, new[] { adminPacket });

            var claim = TestData.CreateUserClaimPrincipal(requestUserId);
            var grantToRequest = TestData.CreatePacketWithRandomGrant(sporadic, packetId, userspaceId, falseWorkGroupId, userId);
            var hasAnyGrant = claim.HasAnyGrant(userspaceId, workGroupId, new[] { grantToRequest.Grants.First() });
            Assert.True(hasAnyGrant);
        }

        [Theory(DisplayName = "GrantsExtensions: HasAllGrants(): Проверка истина при корректном запросе.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyReturnTrueIfUserHasAllGrants(int seed)
        {
            var sporadic = new Random(seed);
            var packetId1 = sporadic.GetId();
            var packetId2 = sporadic.GetId();
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var packetToSet1 = TestData.CreatePacketWithRandomGrant(sporadic, packetId1, userspaceId, workGroupId, userId);
            var packetToSet2 = TestData.CreatePacketWithRandomGrant(sporadic, packetId2, userspaceId, workGroupId, userId);
            var packetsToSet = new[] { packetToSet1, packetToSet2 };

            PacketRepository.Set(userId, packetsToSet);
            var claim = TestData.CreateUserClaimPrincipal(userId);

            var hasAllGrants = claim.HasAllGrants(userspaceId, workGroupId, new[] { packetToSet1.Grants.First(), packetToSet2.Grants.First() });
            Assert.True(hasAllGrants);
        }

        [Theory(DisplayName = "GrantsExtensions: HasAllGrants(): Проверка ложь при некорректном запросе.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnFalseIfUserHasNoSingleGrantOnHasAllGrants(int seed)
        {
            var sporadic = new Random(seed);
            var packetId1 = sporadic.GetId();
            var packetId2 = sporadic.GetId();
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var packetToSet = TestData.CreatePacketWithRandomGrant(sporadic, packetId1, userspaceId, workGroupId, userId);

            PacketRepository.Set(userId, packetToSet);
            var claim = TestData.CreateUserClaimPrincipal(userId);

            var additionalGrantToRequest = TestData.CreatePacketWithRandomGrant(sporadic, packetId2, userspaceId, workGroupId, userId);
            var hasAllGrants = claim.HasAllGrants(userspaceId, workGroupId, new[] { packetToSet.Grants.First(), additionalGrantToRequest.Grants.First() });
            Assert.False(hasAllGrants);
        }

        [Theory(DisplayName = "GrantsExtensions: HasAllGrants(): Проверка ложь при отсутствии соотвествующих рабочих групп.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnFalseIfUserHasNoAppropriateWorkGroupsOnHasAllGrants(int seed)
        {
            var sporadic = new Random(seed);
            var packetId1 = sporadic.GetId();
            var packetId2 = sporadic.GetId();
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var requestedWorkGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var packetToSet = TestData.CreatePacketWithRandomGrant(sporadic, packetId1, userspaceId, workGroupId, userId);

            PacketRepository.Set(userId, packetToSet);
            var claim = TestData.CreateUserClaimPrincipal(userId);

            var additionalGrantToRequest = TestData.CreatePacketWithRandomGrant(sporadic, packetId2, userspaceId, workGroupId, userId);
            var hasAllGrants = claim.HasAllGrants(userspaceId, requestedWorkGroupId, new[] { packetToSet.Grants.First(), additionalGrantToRequest.Grants.First() });
            Assert.False(hasAllGrants);
        }

        [Theory(DisplayName = "GrantsExtensions: HasAllGrants(): Проверка истина для системного пользователя.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnTrueForSystemUserOnHasAllGrantsRequest(int seed)
        {
            var sporadic = new Random(seed);
            var packetId = sporadic.GetId();
            var userId = sporadic.GetId();
            var userspaceId = sporadic.GetId();
            PacketRepository.Set(userId, Array.Empty<PacketViewModel>());
            var workGroupId = sporadic.GetId();

            var claim = TestData.CreateSystemUserClaimPrincipal();
            var grantToRequest = TestData.CreatePacketWithRandomGrant(sporadic, packetId, 10, workGroupId, userId);
            var hasAllGrants = claim.HasAllGrants(userspaceId, workGroupId, new[] { grantToRequest.Grants.First() });
            Assert.True(hasAllGrants);
        }

        [Theory(DisplayName = "GrantsExtensions: HasAllGrants(): Проверка истина администратору пространства даже при ошибке рабочей группы.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnTrueForUserspaceAdminOnHasAllGrantsRequest(int seed)
        {
            var sporadic = new Random(seed);
            var packetId = sporadic.GetId();
            var userId = sporadic.GetId();
            var workGroupId = sporadic.GetId();
            var falseWorkGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var packetToSet = TestData.CreatePacket(packetId, userspaceId, workGroupId, userId);
            PacketRepository.Set(userId, packetToSet);

            var requestUserId = sporadic.GetId();

            var systemPacketMaps = TestData.CreateSystemPacketMaps(_userspaceAdminPacketId, userspaceId);
            PacketRepository.SetSystemPacketMaps(requestUserId, systemPacketMaps);

            var adminPacket = TestData.CreatePacketUserspaceAdmin(_userspaceAdminPacketId, userspaceId, workGroupId, requestUserId);
            PacketRepository.Set(requestUserId, new[] { adminPacket });

            var claim = TestData.CreateUserClaimPrincipal(requestUserId);
            var grantToRequest = TestData.CreatePacketWithRandomGrant(sporadic, packetId, userspaceId, falseWorkGroupId, userId);
            var hasAllGrants = claim.HasAllGrants(userspaceId, workGroupId, new[] { grantToRequest.Grants.First() });
            Assert.True(hasAllGrants);
        }

        [Theory(DisplayName = "GrantsExtensions: IsUserspaceAdmin(): Проверка истина при корректном запросе.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyReturnTrueIfUserIsUserspaceAdmin(int seed)
        {
            var sporadic = new Random(seed);
            var userId = sporadic.GetId();
            PacketRepository.Set(userId, Array.Empty<PacketViewModel>());
            var workGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var systemPacketMaps = TestData.CreateSystemPacketMaps(_userspaceAdminPacketId, userspaceId);
            PacketRepository.SetSystemPacketMaps(userId, systemPacketMaps);

            var packetToSet = TestData.CreatePacketUserspaceAdmin(_userspaceAdminPacketId, userspaceId, workGroupId, userId);
            PacketRepository.Set(userId, packetToSet);

            var claim = TestData.CreateUserClaimPrincipal(userId);

            var isUserspaceAdmin = claim.IsUserspaceAdmin(userspaceId);
            Assert.True(isUserspaceAdmin);
        }

        [Theory(DisplayName = "GrantsExtensions: IsUserspaceAdmin(): Проверка ложь при отсутствии прав.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnFalseIfUserIsNotUserspaceAdmin(int seed)
        {
            var sporadic = new Random(seed);
            var packetId = sporadic.GetId();
            var userId = sporadic.GetId();
            PacketRepository.Set(userId, Array.Empty<PacketViewModel>());
            var workGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var packetToSet = TestData.CreatePacketWithRandomGrant(sporadic, packetId, 10, workGroupId, userId);

            PacketRepository.Set(userId, packetToSet);
            var claim = TestData.CreateUserClaimPrincipal(userId);

            var isUserspaceAdmin = claim.IsUserspaceAdmin(userspaceId);
            Assert.False(isUserspaceAdmin);
        }

        [Fact(DisplayName = "GrantsExtensions: IsSystemUser(): Проверка истина для системного пользователя.")]
        public void ShouldProperlyReturnTrueForSystemUser()
        {
            var claim = TestData.CreateSystemUserClaimPrincipal();

            var isSystemUser = claim.IsSystemUser();
            Assert.True(isSystemUser);
        }

        [Theory(DisplayName = "GrantsExtensions: IsSystemUser(): Проверка ложь для заурядного, посредственного, обычного пользователя.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyReturnFalseForOrdinaryUser(int seed)
        {
            var sporadic = new Random(seed);
            var userId = sporadic.GetId();
            var claim = TestData.CreateUserClaimPrincipal(userId);

            var isSystemUser = claim.IsSystemUser();
            Assert.False(isSystemUser);
        }

        [Fact(DisplayName = "GrantsExtensions: IsSystemUser(): Проверка ложь null в ClaimsPrincipal.")]
        public void ShouldProperlyReturnFalseForNullClaimsPrincipal()
        {
            ClaimsPrincipal claim = null;

            var isSystemUser = claim.IsSystemUser();
            Assert.False(isSystemUser);
        }

        [Theory(DisplayName = "GrantsExtensions: IsSystemUser(): Проверка ложь для неожиданного значения подходящего ключа.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyReturnFalseIfClaimsValueIsQuiteUnexpected(int seed)
        {
            var sporadic = new Random(seed);
            var claimValue = sporadic.GetRandomModuleName();
            var claim = TestData.CreateSystemUserClaimPrincipal(claimValue);

            var isSystemUser = claim.IsSystemUser();
            Assert.False(isSystemUser);
        }

        [Theory(DisplayName = "GrantsExtensions: IsSuperUser(): Проверка истина для системного пользователя.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnTrueForSystemUserSuperUser(int seed)
        {
            var sporadic = new Random(seed);
            var userspaceId = sporadic.GetId();
            var claim = TestData.CreateSystemUserClaimPrincipal();

            var isSuperUser = claim.IsSuperUser(userspaceId);
            Assert.True(isSuperUser);
        }

        [Theory(DisplayName = "GrantsExtensions: IsSuperUser(): Проверка истина для администратора пространства.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnTrueForUserspaceAdminSuperUser(int seed)
        {
            var sporadic = new Random(seed);
            var userId = sporadic.GetId();
            PacketRepository.Set(userId, Array.Empty<PacketViewModel>());
            var workGroupId = sporadic.GetId();
            var userspaceId = sporadic.GetId();

            var systemPacketMaps = TestData.CreateSystemPacketMaps(_userspaceAdminPacketId, userspaceId);
            PacketRepository.SetSystemPacketMaps(userId, systemPacketMaps);

            var packetToSet = TestData.CreatePacketUserspaceAdmin(_userspaceAdminPacketId, userspaceId, workGroupId, userId);
            PacketRepository.Set(userId, packetToSet);

            var claim = TestData.CreateUserClaimPrincipal(userId);

            var isSuperUser = claim.IsSuperUser(userspaceId);
            Assert.True(isSuperUser);
        }

        [Theory(DisplayName = "GrantsExtensions: IsSuperUser(): Проверка ложь для обычного пользователя.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnFalseForNonSuperUser(int seed)
        {
            var sporadic = new Random(seed);
            var userId = sporadic.GetId();
            var userspaceId = sporadic.GetId();
            var claim = TestData.CreateUserClaimPrincipal(userId);

            var isSuperUser = claim.IsSuperUser(userspaceId);
            Assert.False(isSuperUser);
        }

        [Theory(DisplayName = "GrantsExtensions: GetWorkGroupsWithGrant(): Проверка корректного получения списка идентификаторов рабочих групп.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyReturnWorkGroupsWithGrant(int seed)
        {
            var sporadic = new Random(seed);
            var userId = sporadic.GetId();
            var testUserspaceId = sporadic.GetId();
            var invalidUserspaceId = sporadic.GetId();
            PacketRepository.Set(userId, Array.Empty<PacketViewModel>());
            var claim = TestData.CreateUserClaimPrincipal(userId);
            var count = sporadic.Next(7, 64);
            const double probability = .25;
            var workGroups = new List<long>();
            var packets = new List<PacketViewModel>();
            for (var i = 0; i < count; i++)
            {
                if (sporadic.NextDouble() > probability)
                {
                    continue;
                }

                var packet = TestData.CreatePacket(i, testUserspaceId, i, userId);
                packets.Add(packet);
                workGroups.Add(i);
            }

            for (var i = count; i < count + sporadic.Next(64, 70); i++)
            {
                if (sporadic.NextDouble() > probability)
                {
                    continue;
                }
                // Добавляем еще пакеты с правами, только в другое пространство для гругих РГ.
                var packet = TestData.CreatePacket(i, invalidUserspaceId, sporadic.Next(count, count + 10), userId);
                packets.Add(packet);
            }
            AddPacketsToRepository(userId, packets);
            var workGroupsWithGrant = claim.
                GetWorkGroupsWithGrant(testUserspaceId, Modules.GrantType.BaseSystemWorkGroupRolesRead);
            Assert.Equal(workGroups, workGroupsWithGrant);
        }

        [Theory(DisplayName = "GrantsExtensions: GetWorkGroupsWithGrant(): Проверка корректного получения пустого списка при некорректном имени права.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnEmptyIEnumerableForInvalidGrantNameOnGetWorkGroupsWithGrant(int seed)
        {
            var sporadic = new Random(seed);
            var userId = sporadic.GetId();
            var testUserspaceId = sporadic.GetId();
            var invalidUserspaceId = sporadic.GetId();
            PacketRepository.Set(userId, Array.Empty<PacketViewModel>());
            var claim = TestData.CreateUserClaimPrincipal(userId);
            var count = sporadic.Next(16, 64);
            const double probability = .25;
            var packets = new List<PacketViewModel>();
            for (var i = 0; i < count; i++)
            {
                if (sporadic.NextDouble() > probability)
                {
                    continue;
                }

                var packet = TestData.CreatePacket(i, testUserspaceId, i, userId);
                packets.Add(packet);
            }
            for (var i = count; i < count + sporadic.Next(64, 70); i++)
            {
                if (sporadic.NextDouble() > probability)
                {
                    continue;
                }
                // Добавляем еще пакеты с правами, только в другое пространство для гругих РГ.
                var packet = TestData.CreatePacket(i, invalidUserspaceId, sporadic.Next(count, count + 10), userId);
                packets.Add(packet);
            }
            AddPacketsToRepository(userId, packets);
            var grantName = sporadic.GetRandomGrantName();
            var workGroupsWithGrant = claim.GetWorkGroupsWithGrant(testUserspaceId, grantName);

            Assert.Empty(workGroupsWithGrant);
        }

        [Theory(DisplayName = "GrantsExtensions: GetWorkGroupsWithGrant(): Проверка корректного получения пустого списка при пустом запросе.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        public void ShouldProperlyReturnEmptyIEnumerableForEmptyRequestOnGetWorkGroupsWithGrant(int seed)
        {
            var sporadic = new Random(seed);
            var userId = sporadic.GetId();
            var testUserspaceId = sporadic.GetId();
            var invalidUserspaceId = sporadic.GetId();
            PacketRepository.Set(userId, Array.Empty<PacketViewModel>());
            var claim = TestData.CreateUserClaimPrincipal(userId);
            var count = sporadic.Next(16, 64);
            const double probability = .25;
            var packets = new List<PacketViewModel>();
            for (var i = 0; i < count; i++)
            {
                if (sporadic.NextDouble() > probability)
                {
                    continue;
                }

                var packet = TestData.CreatePacket(i, testUserspaceId, userId, i);
                packets.Add(packet);
            }
            for (var i = count; i < count + sporadic.Next(64, 70); i++)
            {
                if (sporadic.NextDouble() > probability)
                {
                    continue;
                }
                // Добавляем еще пакеты с правами, только в другое пространство для гругих РГ.
                var packet = TestData.CreatePacket(i, invalidUserspaceId, sporadic.Next(count, count + 10), userId);
                packets.Add(packet);
            }
            AddPacketsToRepository(userId, packets);
            var workGroupsWithGrant = claim.GetWorkGroupsWithGrant(testUserspaceId, string.Empty);
            Assert.Empty(workGroupsWithGrant);
        }

        [Theory(DisplayName = "GrantsExtensions: GetWorkGroupsWithAnyGrant(): Проверка корректного получения списка идентификаторов рабочих групп.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyReturnWorkGroupsWithAnyGrant(int seed)
        {
            var sporadic = new Random(seed);
            var userId = sporadic.GetId();
            var testUserspaceId = sporadic.GetId();
            var invalidUserspaceId = sporadic.GetId();
            PacketRepository.Set(userId, Array.Empty<PacketViewModel>());
            var claim = TestData.CreateUserClaimPrincipal(userId);
            var packet1 = TestData.CreatePacketWithRandomGrant(sporadic, 0, testUserspaceId, 0, userId);
            var packet2 = TestData.CreatePacketWithRandomGrant(sporadic, 0, testUserspaceId, 0, userId);
            var packet3 = TestData.CreatePacketWithRandomGrant(sporadic, 0, invalidUserspaceId, 0, userId);
            var count = sporadic.Next(32, 128);
            const double probability = .125;
            var workGroups = new HashSet<long>();
            var packets = new List<PacketViewModel>();
            for (var i = 0; i < count; i++)
            {
                if (sporadic.NextDouble() > probability)
                {
                    continue;
                }

                var packet = GetRoboMutantPacketClone(2 * i, i, packet1);
                packets.Add(packet);
                workGroups.Add(i);
            }
            for (var i = 0; i < count; i++)
            {
                if (sporadic.NextDouble() > probability)
                {
                    continue;
                }

                var packet = GetRoboMutantPacketClone(2 * i + 1, i, packet2);
                packets.Add(packet);
                workGroups.Add(i);
            }
            for (var i = 0; i < count; i++)
            {
                if (sporadic.NextDouble() > probability)
                {
                    continue;
                }

                var packet = GetRoboMutantPacketClone(count + 2 * i, i, packet3);
                packets.Add(packet);
            }
            AddPacketsToRepository(userId, packets);
            var workGroupsWithAnyGrant = claim.GetWorkGroupsWithAnyGrant(testUserspaceId, new[] { packet1.Grants.First(), packet2.Grants.First(), packet3.Grants.First() });
            Assert.Equal(workGroups, workGroupsWithAnyGrant);
        }

        [Theory(DisplayName = "GrantsExtensions: GetWorkGroupsWithAllGrants(): Проверка корректного получения списка идентификаторов рабочих групп.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyReturnWorkGroupsWithAllGrants(int seed)
        {
            var sporadic = new Random(seed);
            var userId = sporadic.GetId();
            var testUserspaceId = sporadic.GetId();
            var invalidUserspaceId = sporadic.GetId();
            PacketRepository.Set(userId, Array.Empty<PacketViewModel>());
            var claim = TestData.CreateUserClaimPrincipal(userId);
            var packet1 = TestData.CreatePacketWithRandomGrant(sporadic, 0, testUserspaceId, 0, userId);
            var packet2 = TestData.CreatePacketWithRandomGrant(sporadic, 0, testUserspaceId, 0, userId);
            var packet2evilTwin = TestData.CreatePacketWithGrant(0, invalidUserspaceId, 0, userId, packet2.Grants.First());
            var count = sporadic.Next(32, 128);
            const double probability = .33;
            var workGroupsWithGrant1 = new List<long>();
            var workGroupsWithGrant2 = new List<long>();
            var packets = new List<PacketViewModel>();
            for (var i = 0; i < count; i++)
            {
                if (sporadic.NextDouble() > probability)
                {
                    continue;
                }

                var packet = GetRoboMutantPacketClone(2 * i, i, packet1);
                packets.Add(packet);
                workGroupsWithGrant1.Add(i);
            }
            for (var i = 0; i < count; i++)
            {
                if (sporadic.NextDouble() > probability)
                {
                    continue;
                }

                var packet = GetRoboMutantPacketClone(2 * i + 1, i, packet2);
                packets.Add(packet);
                workGroupsWithGrant2.Add(i);
            }
            for (var i = 0; i < count; i++)
            {
                var packet = GetRoboMutantPacketClone(count + 2 * i, i, packet2evilTwin);
                packets.Add(packet);
            }
            AddPacketsToRepository(userId, packets);
            var expectedWorkGroups = workGroupsWithGrant1.Intersect(workGroupsWithGrant2);

            var workGroupsWithAllGrants = claim.GetWorkGroupsWithAllGrants(testUserspaceId, new[] { packet1.Grants.First(), packet2.Grants.First() });
            Assert.Equal(expectedWorkGroups, workGroupsWithAllGrants);
        }

        [Theory(DisplayName = "GrantsExtensions: WorkGroups(): Проверка корректного получения списка идентификаторов рабочих групп.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyReturnUserWorkGroups(int seed)
        {
            var sporadic = new Random(seed);
            var userId = sporadic.GetId();
            PacketRepository.Set(userId, Array.Empty<PacketViewModel>());
            var claim = TestData.CreateUserClaimPrincipal(userId);
            var count = sporadic.Next(4, 16);
            var workGroups = new List<long>();
            var packets = new List<PacketViewModel>();
            for (var i = 0; i < count; i++)
            {
                var workGroupIds = Enumerable.Range(1, sporadic.Next(1, 5))
                    .Select(_ => sporadic.GetId())
                    .ToList();
                var packet = TestData.CreatePacketWithMultipleWorkGroups(i, 10, workGroupIds, userId);
                packets.Add(packet);
                workGroups.AddRange(workGroupIds);
            }
            AddPacketsToRepository(userId, packets);
            var result = claim.WorkGroups(10);

            Assert.Equal(workGroups, result);
        }

        [Theory(DisplayName = "GrantsExtensions: Userspaces(): Проверка корректного получения списка идентификаторов пространств пользователя.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyReturnUserspaces(int seed)
        {
            var sporadic = new Random(seed);
            var userId = sporadic.GetId();
            PacketRepository.Set(userId, Array.Empty<PacketViewModel>());
            var claim = TestData.CreateUserClaimPrincipal(userId);
            var count = sporadic.Next(4, 16);
            var userspaces = new List<long>();
            var packets = new List<PacketViewModel>();
            for (var i = 0; i < count; i++)
            {
                var workGroupIds = Enumerable.Range(1, sporadic.Next(1, 5))
                    .Select(_ => sporadic.GetId())
                    .ToList();
                var packet = TestData.CreatePacketWithMultipleWorkGroups(i, i, workGroupIds, userId);
                packets.Add(packet);
                userspaces.Add(i);
            }
            AddPacketsToRepository(userId, packets);
            var result = claim.Userspaces();

            Assert.Equal(userspaces, result);
        }

        [Theory(DisplayName = "GrantsExtensions: Userspace(): Проверка корректного получения идентификатора пользовательского пространства из заголовков запроса.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldProperlyGetUserspaceIdFromRequestHeadersOnUserspace(int seed)
        {
            var sporadic = new Random(seed);
            var httpContext = new DefaultHttpContext();

            var userspaceId = sporadic.GetId();
            httpContext.Request.Headers.Add("x-smon-userspace-id", new StringValues(userspaceId.ToString()));

            var result = httpContext.Request.Userspace();
            Assert.Equal(userspaceId, result);
        }

        [Theory(DisplayName = "GrantsExtensions: Userspace(): Выбросить исключение, при некорректно заданном значении пространства пользователя в заголовке запроса.")]
        [InlineData(sbyte.MaxValue)]
        [InlineData(byte.MaxValue)]
        [InlineData(short.MaxValue)]
        [InlineData(ushort.MaxValue)]
        public void ShouldThrowExceptionForNonNumericStringInUserspaceHeaders(int seed)
        {
            var sporadic = new Random(seed);
            var httpContext = new DefaultHttpContext();

            var userspaceId = sporadic.GetRandomModuleName();
            httpContext.Request.Headers.Add("x-smon-userspace-id", new StringValues(userspaceId));

            const string expectedResult = "Невозможно выполнить преобразование id пространства пользователя из заголовка x-smon-userspace-id в корректное значение.";
            var result = Assert.Throws<UserspaceNotFoundException>(() => httpContext.Request.Userspace());
            Assert.Equal(expectedResult, result.Message);
        }

        [Fact(DisplayName = "GrantsExtensions: Userspace(): Выбросить исключение, если заголовок с пространством пользователя в запросе имел пустое значение.")]
        public void ShouldThrowExceptionForEmptyValueInUserspaceHeaders()
        {
            var httpContext = new DefaultHttpContext();

            httpContext.Request.Headers.Add("x-smon-userspace-id", new StringValues());

            const string expectedResult = "Не указан заголовок x-smon-userspace-id.";
            var result = Assert.Throws<UserspaceNotFoundException>(() => httpContext.Request.Userspace());
            Assert.Equal(expectedResult, result.Message);
        }

        [Fact(DisplayName = "GrantsExtensions: Userspace(): Выбросить исключение, если не найден заголовок с пространством пользователя в запросе.")]
        public void ShouldThrowExceptionForNonExistentUserspaceHeader()
        {
            var httpContext = new DefaultHttpContext();

            const string expectedResult = "Не указан заголовок x-smon-userspace-id.";
            var result = Assert.Throws<UserspaceNotFoundException>(() => httpContext.Request.Userspace());
            Assert.Equal(expectedResult, result.Message);
        }

        void AddPacketsToRepository(long userId, IEnumerable<PacketViewModel> packets)
        {
            var existingPackets = PacketRepository.Get(userId);
            existingPackets = existingPackets.Union(packets);
            PacketRepository.Set(userId, existingPackets);
        }

        PacketViewModel GetRoboMutantPacketClone(long id, long workGroupId, PacketViewModel packet)
        {
            var userId = packet?.Owners?.FirstOrDefault()?.Users?.FirstOrDefault() ?? 0;
            return GetRobotMutantPacketClone(id, workGroupId, userId, packet);
        }

        PacketViewModel GetRobotMutantPacketClone(long id, long workGroupId, long userId, PacketViewModel packet)
        {
            var json = JsonConvert.SerializeObject(packet);                         // Robot Mutant Packet Clones (x4)
            var packetClone = JsonConvert.DeserializeObject<PacketViewModel>(json); // They're the world's most fearsome fighting team

            packetClone.Id = id;                                                    // They're heroes in a metall shell and they're creep
            packetClone.Owners.First().WorkGroupId = workGroupId;                   // When the evil Debugger attacks
            packetClone.Owners.First().Users = new[] { userId };                    // These Robot boys don't cut him no slack!

            return packetClone;                                                     // Robot Mutant Packet Clones (x4)
        }
    }
}