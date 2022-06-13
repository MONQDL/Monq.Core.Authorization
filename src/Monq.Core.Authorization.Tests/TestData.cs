using IdentityModel;
using Monq.Core.Authorization.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Monq.Core.Authorization.Tests
{
    public static class TestData
    {
        public static PacketViewModel CreatePacket(in long packetId, in long userspaceId, in long workGroupId, in long userId) =>
            CreatePacketWithMultipleWorkGroups(packetId, userspaceId, new[] { workGroupId }, userId);

        public static PacketViewModel CreatePacketWithMultipleWorkGroups(long packetId, long userspaceId, IEnumerable<long> workGroupIds, long userId) =>
            new PacketViewModel
            {
                Id = packetId,
                Owners = workGroupIds.Select(val => new PacketOwnerViewModel
                {
                    PacketId = packetId,
                    WorkGroupId = val,
                    UserspaceId = userspaceId,
                    Users = new[] { userId }
                }),
                Grants = new[]
                {
                    Modules.GrantType.BaseSystemWorkGroupRolesRead
                }
            };

        public static PacketViewModel CreatePacketWithRandomGrant(Random sporadic, in long packetId, in long userspaceId, in long workGroupId, in long userId) =>
            new PacketViewModel
            {
                Id = packetId,
                Owners = new[]
                {
                    new PacketOwnerViewModel
                    {
                        PacketId = packetId,
                        WorkGroupId = workGroupId,
                        UserspaceId = userspaceId,
                        Users = new[] { userId }
                    }
                },
                Grants = new[]
                {
                    sporadic.GetRandomGrantName()
                }
            };

        public static PacketViewModel CreatePacketWithGrant(in long packetId, in long userspaceId, in long workGroupId, in long userId, string grantName) =>
            new PacketViewModel
            {
                Id = packetId,
                Owners = new[]
                {
                    new PacketOwnerViewModel
                    {
                        PacketId = packetId,
                        WorkGroupId = workGroupId,
                        UserspaceId = userspaceId,
                        Users = new[] { userId }
                    }
                },
                Grants = new[]
                {
                    grantName
                }
            };

        public static PacketViewModel CreatePacketWithCloudAdminGrant(in long packetId, in long workGroupId, in long userId) =>
            CreatePacketUserspaceAdmin(packetId, 0, workGroupId, userId);

        public static PacketViewModel CreatePacketUserspaceAdmin(in long packetId, in long userspaceId, in long workGroupId, in long userId) =>
            new PacketViewModel
            {
                Id = packetId,
                Owners = new[]
                {
                    new PacketOwnerViewModel
                    {
                        PacketId = packetId,
                        UserspaceId = userspaceId,
                        WorkGroupId = workGroupId,
                        Users = new[] { userId }
                    }
                },
                Grants = new[]
                {
                    Modules.GrantType.CloudManagementGrantsMetaWrite,
                    Modules.GrantType.AdminsUserEntitiesWrite
                }
            };

        public static PacketViewModel CreatePacketWithUserEntitiesGrant(in long packetId, in long userspaceId, in long workGroupId, in long userId) =>
            new PacketViewModel
            {
                Id = packetId,
                Owners = new[]
                {
                    new PacketOwnerViewModel
                    {
                        PacketId = packetId,
                        UserspaceId = userspaceId,
                        WorkGroupId = workGroupId,
                        Users = new[] { userId }
                    }
                },
                Grants = new[]
                {
                    Modules.GrantType.AdminsUserEntitiesWrite
                }
            };

        public static ClaimsPrincipal CreateUserClaimPrincipal(in long id)
        {
            var claims = new Claim[] { new Claim(JwtClaimTypes.Subject, id.ToString()) };
            var ci = new ClaimsIdentity(claims, "", JwtClaimTypes.Name, JwtClaimTypes.Role);
            return new ClaimsPrincipal(ci);
        }

        public static ClaimsPrincipal CreateSystemUserClaimPrincipal(string value = "smon-res-owner")
        {
            var claims = new Claim[] { new Claim(JwtClaimTypes.ClientId, value) };
            var ci = new ClaimsIdentity(claims, "", JwtClaimTypes.Name, JwtClaimTypes.Role);
            return new ClaimsPrincipal(ci);
        }

        public static long GetId(this Random sporadic) =>
            sporadic.Next(1, long.MaxValue);

        public static long Next(this Random sporadic, in long min, in long max)
        {
            var buf = new byte[8];
            sporadic.NextBytes(buf);
            var longRand = BitConverter.ToInt64(buf, 0);

            return Math.Abs(longRand % (max - min)) + min;
        }

        public static string GetRandomGrantName(this Random sporadic) =>
            $"{GetRandomModuleName(sporadic)}.{GetRandomModuleName(sporadic)}.{GetRandomModuleName(sporadic)}";

        public static string GetRandomModuleName(this Random sporadic) =>
            InsertRandomDashes(sporadic,
                GetRandomString(sporadic,
                    sporadic.Next(8, 17)));

        // Toki Pona `kalama` ;^P
        static string GetRandomString(Random sporadic, in int length = 6, string chars = "aeiouwjptksmnl") =>
            new string(Enumerable.Repeat(chars, length)
                .Select(s => s[sporadic.Next(s.Length)]).ToArray());

        static string InsertRandomDashes(Random sporadic, string input, in double probability = .1) =>
            InsertCharsSporadically(sporadic, input, '-', probability);

        static string InsertCharsSporadically(Random sporadic, string input, char character, double probalility = .5) =>
            input.Aggregate(
                string.Empty,
                (result, currentChar) =>
                    sporadic.NextDouble() <= probalility
                    ? result + currentChar + character
                    : result + currentChar);
    }
}
