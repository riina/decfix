using System.Text.Json.Serialization;

namespace decfix;

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(string[]))]
internal partial class SourceGenerationContext : JsonSerializerContext
{
}
