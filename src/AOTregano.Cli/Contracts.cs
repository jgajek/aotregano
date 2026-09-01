using System.Text.Json.Serialization;

namespace AOTregano.Cli;

internal sealed record AddressValue(ulong Value, string Hex)
{
    public static AddressValue Of(ulong value) => new(value, $"0x{value:X}");
}

internal sealed record RecognitionInfo(
    bool NativeAot,
    AddressValue ReadyToRunHeader,
    ushort MajorVersion,
    ushort MinorVersion,
    byte DirectoryEntrySize,
    byte DirectoryEntryType,
    int Sections);

internal sealed record HydrationInfo(string State, ulong BytesWritten);

internal sealed record RecoveryCounts(
    int PointerCandidates,
    int MethodTables,
    int Strings,
    int Arrays,
    int Annotations);

internal sealed record RunOutputs(
    string Analysis,
    string Sections,
    string MethodTables,
    string Strings,
    string Arrays,
    string Annotations,
    string MappedImage);

internal sealed record IntegrityInfo(string Path, long Length, string Sha256);

internal sealed record RunManifest(
    string Schema,
    string ToolVersion,
    bool Success,
    string InputPath,
    string InputSha256,
    long InputLength,
    string Format,
    string TargetOs,
    string Architecture,
    AddressValue ImageBase,
    AddressValue EntryPoint,
    int MappedImageLength,
    RecognitionInfo Recognition,
    HydrationInfo Hydration,
    RecoveryCounts Recovery,
    RunOutputs Wrote,
    IReadOnlyDictionary<string, IntegrityInfo> ArtifactIntegrity,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Log,
    IReadOnlyList<string> Limitations,
    IReadOnlyList<string> Blockers,
    bool MoreWorkPossible)
{
    public const string Current = "aotregano.run/1";
}

internal sealed record RunFailure(
    string Schema,
    string ToolVersion,
    bool Success,
    string ErrorKind,
    string Error,
    string? InputPath,
    string? InputSha256,
    long? InputLength,
    bool MoreWorkPossible)
{
    public const string Current = "aotregano.error/1";
}

internal sealed record SectionRow(
    uint Type,
    string Name,
    uint Flags,
    AddressValue Start,
    AddressValue End,
    ulong Size);

internal sealed record MethodTableRow(
    AddressValue Address,
    string Name,
    string Layout,
    int ElementType,
    string ElementTypeName,
    ushort ComponentSize,
    uint Flags,
    uint BaseSize,
    AddressValue RelatedType,
    ushort VTableSlotCount,
    ushort InterfaceCount,
    uint HashCode,
    IReadOnlyList<AddressValue> VTable,
    IReadOnlyList<AddressValue> Interfaces);

internal sealed record StringRow(AddressValue Address, int Length, string Name, string Value);
internal sealed record ArrayRow(AddressValue Address, int Length, string ElementType, string Name);
internal sealed record AnnotationRow(AddressValue Address, string Kind, string Name, string? Value);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified)]
[JsonSerializable(typeof(RunManifest))]
[JsonSerializable(typeof(RunFailure))]
[JsonSerializable(typeof(IReadOnlyList<SectionRow>))]
[JsonSerializable(typeof(SectionRow))]
[JsonSerializable(typeof(MethodTableRow))]
[JsonSerializable(typeof(StringRow))]
[JsonSerializable(typeof(ArrayRow))]
[JsonSerializable(typeof(AnnotationRow))]
internal partial class AOTreganoJsonContext : JsonSerializerContext;
