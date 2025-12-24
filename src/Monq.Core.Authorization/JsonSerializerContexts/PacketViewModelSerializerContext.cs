using Monq.Core.Authorization.Models;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Monq.Core.Authorization.JsonSerializerContexts;

[JsonSerializable(typeof(IEnumerable<PacketViewModel>))]
[JsonSourceGenerationOptions(UseStringEnumConverter = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DictionaryKeyPolicy = JsonKnownNamingPolicy.CamelCase)]
internal partial class PacketViewModelSerializerContext : JsonSerializerContext
{
}
