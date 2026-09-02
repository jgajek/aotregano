using System.Buffers;
using System.Buffers.Binary;

namespace AOTregano.Core;

public static class ReadyToRunSectionType
{
    public const uint FrozenObjectRegion = 206;
    public const uint DehydratedData = 207;

    public static string Name(uint type) => type switch
    {
        100 => "CompilerIdentifier",
        101 => "ImportSections",
        102 => "RuntimeFunctions",
        103 => "MethodDefEntryPoints",
        104 => "ExceptionInfo",
        105 => "DebugInfo",
        106 => "DelayLoadMethodCallThunks",
        108 => "AvailableTypes",
        109 => "InstanceMethodEntryPoints",
        110 => "InliningInfo",
        111 => "ProfileDataInfo",
        112 => "ManifestMetadata",
        113 => "AttributePresence",
        114 => "InliningInfo2",
        115 => "ComponentAssemblies",
        116 => "OwnerCompositeExecutable",
        117 => "PgoInstrumentationData",
        118 => "ManifestAssemblyMvids",
        119 => "CrossModuleInlineInfo",
        120 => "HotColdMap",
        121 => "MethodIsGenericMap",
        122 => "EnclosingTypeMap",
        123 => "TypeGenericInfoMap",
        124 => "ExternalTypeMaps",
        125 => "ProxyTypeMaps",
        126 => "TypeMapAssemblyTargets",
        200 => "StringTable",
        201 => "GCStaticRegion",
        202 => "ThreadStaticRegion",
        204 => "TypeManagerIndirection",
        205 => "EagerCctor",
        FrozenObjectRegion => "FrozenObjectRegion",
        DehydratedData => "DehydratedData",
        208 => "ThreadStaticOffsetRegion",
        209 => "InterfaceDispatchCellInfoRegion",
        210 => "InterfaceDispatchCellRegion",
        212 => "ImportAddressTables",
        213 => "ModuleInitializerList",
        214 => "GvmDispatchCellInfoRegion",
        215 => "GvmDispatchCellRegion",
        >= 300 and <= 399 => $"ReadonlyBlob_{type}",
        _ => $"Unknown_{type}"
    };
}

public sealed record ReadyToRunSection(uint Type, uint Flags, ulong Start, ulong End)
{
    public ulong Size => End >= Start ? End - Start : 0;
    public string Name => ReadyToRunSectionType.Name(Type);
}

public sealed record ReadyToRunHeader(
    ulong Address,
    ushort MajorVersion,
    ushort MinorVersion,
    uint Attributes,
    byte EntrySize,
    byte EntryType,
    IReadOnlyList<ReadyToRunSection> Sections)
{
    private const uint Signature = 0x0052_5452;

    public ReadyToRunSection? GetSection(uint type) => Sections.FirstOrDefault(section => section.Type == type);

    public static ReadyToRunHeader? TryParse(MemoryImage memory, ulong address)
    {
        try
        {
            if (memory.ReadU32(address) != Signature)
                return null;
            var major = memory.ReadU16(address + 4);
            var minor = memory.ReadU16(address + 6);
            var attributes = memory.ReadU32(address + 8);
            var sectionCount = memory.ReadU16(address + 12);
            var entrySize = memory.ReadU8(address + 14);
            var entryType = memory.ReadU8(address + 15);
            if (sectionCount is 0 or > 80 || entrySize is not (16 or 24) || entryType != 1)
                return null;

            var sections = new List<ReadyToRunSection>(sectionCount);
            var cursor = address + 16;
            for (var index = 0; index < sectionCount; index++, cursor += entrySize)
            {
                var type = memory.ReadU32(cursor);
                uint flags;
                ulong start;
                ulong end;
                if (entrySize == 16)
                {
                    // NativeAOT v18+ uses type, byte size, and absolute start VA.
                    var size = memory.ReadU32(cursor + 4);
                    flags = 0;
                    start = memory.ReadU64(cursor + 8);
                    end = start == 0 ? 0 : checked(start + size);
                }
                else
                {
                    flags = memory.ReadU32(cursor + 4);
                    start = memory.ReadU64(cursor + 8);
                    end = memory.ReadU64(cursor + 16);
                }
                if (start != 0 && !memory.Contains(start))
                    return null;
                if (end != 0 && (end < start || end > start && !memory.Contains(end - 1)))
                    return null;
                sections.Add(new ReadyToRunSection(type, flags, start, end));
            }
            return new ReadyToRunHeader(
                address, major, minor, attributes, entrySize, entryType, sections);
        }
        catch (Exception exception) when (exception is InvalidDataException or OverflowException)
        {
            return null;
        }
    }

    public static IReadOnlyList<ReadyToRunHeader> Locate(MemoryImage memory)
    {
        Span<byte> needle = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(needle, Signature);
        var headers = new Dictionary<ulong, ReadyToRunHeader>();
        foreach (var section in memory.Sections.Where(section => section.IsInitialized && !section.IsExecutable))
        {
            if (section.RawSize > int.MaxValue)
                continue;
            var sectionAddress = checked(memory.ImageBase + section.VirtualAddress);
            var data = memory.Read(sectionAddress, checked((int)section.RawSize));
            var consumed = 0;
            while (consumed <= data.Length - needle.Length)
            {
                var hit = data[consumed..].IndexOf(needle);
                if (hit < 0)
                    break;
                var candidate = checked(sectionAddress + (ulong)consumed + (ulong)hit);
                var parsed = TryParse(memory, candidate);
                if (parsed is not null)
                    headers.TryAdd(candidate, parsed);
                consumed += hit + 1;
            }
        }
        return headers.Values
            .OrderBy(header => header.GetSection(ReadyToRunSectionType.DehydratedData) is null ? 1 : 0)
            .ThenBy(header => header.GetSection(ReadyToRunSectionType.FrozenObjectRegion) is null ? 1 : 0)
            .ThenBy(header => header.Address)
            .ToArray();
    }
}

public sealed record OrphanedReadyToRunDirectory(
    ulong Address,
    IReadOnlyList<ReadyToRunSection> Sections)
{
    private const int EntrySize = 24;

    public ReadyToRunSection? GetSection(uint type) =>
        Sections.FirstOrDefault(section => section.Type == type);

    public static IReadOnlyList<OrphanedReadyToRunDirectory> Locate(MemoryImage memory)
    {
        var destinations = memory.Sections
            .Where(section =>
                section.RawSize == 0 && section.VirtualSize > 0 &&
                section.Name.Contains("hydrat", StringComparison.OrdinalIgnoreCase))
            .Select(section => checked(memory.ImageBase + section.VirtualAddress))
            .ToHashSet();
        AddMergedHydrationDestinations(memory, destinations);
        if (destinations.Count == 0)
            return [];

        var results = new Dictionary<ulong, OrphanedReadyToRunDirectory>();
        foreach (var container in memory.Sections.Where(section =>
                     section.IsInitialized && !section.IsExecutable))
        {
            var containerStart = checked(memory.ImageBase + container.VirtualAddress);
            var containerEnd = checked(containerStart + container.RawSize);
            var cursor = checked(containerStart + ((8 - (containerStart & 7)) & 7));
            while (cursor <= containerEnd && containerEnd - cursor >= EntrySize)
            {
                if (TryReadEntry(memory, cursor, out var anchor) &&
                    anchor.Type == ReadyToRunSectionType.DehydratedData &&
                    anchor.Size > 4 &&
                    TryReadRelativePointer(memory, anchor.Start, out var destination) &&
                    destinations.Contains(destination))
                {
                    var start = cursor;
                    var firstType = anchor.Type;
                    while (start >= containerStart + EntrySize &&
                           TryReadEntry(memory, start - EntrySize, out var previous) &&
                           previous.Type < firstType)
                    {
                        start -= EntrySize;
                        firstType = previous.Type;
                    }

                    var sections = new List<ReadyToRunSection>();
                    var entryAddress = start;
                    uint lastType = 0;
                    while (entryAddress <= containerEnd &&
                           containerEnd - entryAddress >= EntrySize &&
                           TryReadEntry(memory, entryAddress, out var entry) &&
                           entry.Type > lastType)
                    {
                        sections.Add(entry);
                        lastType = entry.Type;
                        entryAddress += EntrySize;
                    }
                    if (sections.Any(section =>
                            section.Type == ReadyToRunSectionType.FrozenObjectRegion) &&
                        sections.Any(section =>
                            section.Type == ReadyToRunSectionType.DehydratedData))
                    {
                        results.TryAdd(start, new OrphanedReadyToRunDirectory(start, sections));
                    }
                }
                cursor += 8;
            }
        }
        return results.Values.OrderBy(directory => directory.Address).ToArray();
    }

    private static void AddMergedHydrationDestinations(
        MemoryImage memory,
        HashSet<ulong> destinations)
    {
        ReadOnlySpan<byte> name = "hydrated\0"u8;
        foreach (var container in memory.Sections.Where(section =>
                     section.IsInitialized && !section.IsExecutable &&
                     section.RawSize <= int.MaxValue))
        {
            var containerAddress = checked(memory.ImageBase + container.VirtualAddress);
            var data = memory.Read(containerAddress, checked((int)container.RawSize));
            var consumed = 0;
            while (consumed <= data.Length - name.Length)
            {
                var hit = data[consumed..].IndexOf(name);
                if (hit < 0)
                    break;
                var nameOffset = consumed + hit;
                if (nameOffset >= 8)
                {
                    var startRva = BinaryPrimitives.ReadUInt32LittleEndian(
                        data.Slice(nameOffset - 8, 4));
                    var size = BinaryPrimitives.ReadUInt32LittleEndian(
                        data.Slice(nameOffset - 4, 4));
                    ImageSection? parent = null;
                    foreach (var section in memory.Sections)
                    {
                        if (section.VirtualAddress <= startRva &&
                            size > 0 &&
                            (ulong)startRva + size <= section.EndRva)
                        {
                            parent = section;
                            break;
                        }
                    }
                    if (parent is not null &&
                        startRva >= parent.VirtualAddress + parent.RawSize)
                    {
                        destinations.Add(checked(memory.ImageBase + startRva));
                    }
                }
                consumed = nameOffset + 1;
            }
        }
    }

    private static bool TryReadEntry(
        MemoryImage memory,
        ulong address,
        out ReadyToRunSection entry)
    {
        entry = default!;
        if (!memory.Contains(address, EntrySize))
            return false;
        var type = memory.ReadU32(address);
        var flags = memory.ReadU32(address + 4);
        var start = memory.ReadU64(address + 8);
        var end = memory.ReadU64(address + 16);
        if (type is < 100 or > 399 || flags > 0xFFFF || end < start)
            return false;
        if (start != 0 && (!memory.Contains(start) || end == start))
            return false;
        if (end != 0 && !memory.Contains(end - 1))
            return false;
        entry = new ReadyToRunSection(type, flags, start, end);
        return true;
    }

    private static bool TryReadRelativePointer(
        MemoryImage memory,
        ulong field,
        out ulong target)
    {
        target = 0;
        try
        {
            var delta = memory.ReadI32(field);
            target = delta >= 0
                ? checked(field + (ulong)delta)
                : checked(field - (ulong)(-(long)delta));
            return true;
        }
        catch (Exception exception) when (
            exception is InvalidDataException or OverflowException)
        {
            return false;
        }
    }
}

public sealed record PointerScan(ulong Start, ulong End, IReadOnlyList<ulong> Locations)
{
    public bool Contains(ulong address) => Start <= address && address < End;
}

public static class MetadataRehydrator
{
    public const byte Copy = 0;
    public const byte ZeroFill = 1;
    public const byte RelativePointerRelocation = 2;
    public const byte PointerRelocation = 3;
    public const byte InlineRelativePointerRelocation = 4;
    public const byte InlinePointerRelocation = 5;

    private const int MaximumShortPayload = 28;

    public static PointerScan Rehydrate(
        MemoryImage memory,
        ReadyToRunSection dehydrated,
        ICollection<string>? log = null)
    {
        if (dehydrated.End <= dehydrated.Start)
            throw new InvalidDataException("DehydratedData is empty.");
        var cursor = dehydrated.Start;
        var destination = ReadRelativePointer(memory, cursor);
        cursor += 4;
        var fixups = dehydrated.End;
        var hydrated = new ArrayBufferWriter<byte>();
        var pointerLocations = new List<ulong>();

        while (cursor < dehydrated.End)
        {
            var (command, payload, next) = ReadCommand(memory, cursor, dehydrated.End);
            cursor = next;
            switch (command)
            {
                case Copy:
                    EnsureCapacity(memory, destination, hydrated.WrittenCount, payload);
                    EnsureCommandBytes(cursor, dehydrated.End, payload);
                    hydrated.Write(memory.Read(cursor, payload));
                    cursor = checked(cursor + (uint)payload);
                    break;
                case ZeroFill:
                    EnsureCapacity(memory, destination, hydrated.WrittenCount, payload);
                    hydrated.GetSpan(payload)[..payload].Clear();
                    hydrated.Advance(payload);
                    break;
                case RelativePointerRelocation:
                {
                    EnsureCapacity(memory, destination, hydrated.WrittenCount, 4);
                    var target = ReadFixup(memory, fixups, payload);
                    var field = checked(destination + (ulong)hydrated.WrittenCount);
                    WriteI32(hydrated, RelativeDelta(target, field));
                    break;
                }
                case PointerRelocation:
                {
                    EnsureCapacity(memory, destination, hydrated.WrittenCount, 8);
                    var target = ReadFixup(memory, fixups, payload);
                    pointerLocations.Add(checked(destination + (ulong)hydrated.WrittenCount));
                    WriteU64(hydrated, target);
                    break;
                }
                case InlineRelativePointerRelocation:
                    EnsureCommandBytes(cursor, dehydrated.End, checked(payload * 4));
                    EnsureCapacity(
                        memory, destination, hydrated.WrittenCount, checked(payload * 4));
                    for (var index = 0; index < payload; index++)
                    {
                        var target = ReadRelativePointer(memory, cursor);
                        var field = checked(destination + (ulong)hydrated.WrittenCount);
                        WriteI32(hydrated, RelativeDelta(target, field));
                        cursor += 4;
                    }
                    break;
                case InlinePointerRelocation:
                    EnsureCommandBytes(cursor, dehydrated.End, checked(payload * 4));
                    EnsureCapacity(
                        memory, destination, hydrated.WrittenCount, checked(payload * 8));
                    for (var index = 0; index < payload; index++)
                    {
                        var target = ReadRelativePointer(memory, cursor);
                        pointerLocations.Add(checked(destination + (ulong)hydrated.WrittenCount));
                        WriteU64(hydrated, target);
                        cursor += 4;
                    }
                    break;
                default:
                    throw new InvalidDataException(
                        $"Unknown DehydratedData command 0x{command:X2} at 0x{cursor:X}.");
            }
        }

        memory.Patch(destination, hydrated.WrittenSpan);
        log?.Add($"Rehydrated 0x{hydrated.WrittenCount:X} bytes into 0x{destination:X}.");
        return new PointerScan(
            destination,
            checked(destination + (ulong)hydrated.WrittenCount),
            pointerLocations);
    }

    public static PointerScan ScanPointers(MemoryImage memory, ICollection<string>? log = null)
    {
        var locations = new List<ulong>();
        foreach (var section in memory.Sections.Where(section => !section.IsExecutable))
        {
            var start = checked(memory.ImageBase + section.VirtualAddress);
            var end = checked(memory.ImageBase + section.EndRva);
            var current = checked(start + ((8 - (start & 7)) & 7));
            while (current <= end && end - current >= 8)
            {
                if (!memory.Contains(current, 8))
                    break;
                var value = memory.ReadU64(current);
                if (memory.Contains(value))
                    locations.Add(current);
                current += 8;
            }
        }
        log?.Add($"Manual pointer scan found {locations.Count} candidate pointers.");
        return new PointerScan(memory.ImageBase, checked(memory.ImageBase + (ulong)memory.Length), locations);
    }

    private static (byte Command, int Payload, ulong Cursor) ReadCommand(
        MemoryImage memory, ulong cursor, ulong commandEnd)
    {
        EnsureCommandBytes(cursor, commandEnd, 1);
        var opcode = memory.ReadU8(cursor++);
        var command = (byte)(opcode & 0x07);
        var payload = opcode >> 3;
        var extraBytes = payload - MaximumShortPayload;
        if (extraBytes > 0)
        {
            EnsureCommandBytes(cursor, commandEnd, extraBytes);
            payload = memory.ReadU8(cursor++);
            if (extraBytes > 1)
                payload |= memory.ReadU8(cursor++) << 8;
            if (extraBytes > 2)
                payload |= memory.ReadU8(cursor++) << 16;
            payload += MaximumShortPayload;
        }
        return (command, payload, cursor);
    }

    private static void EnsureCommandBytes(ulong cursor, ulong end, int count)
    {
        if (count < 0 || cursor > end || (ulong)count > end - cursor)
            throw new InvalidDataException("Truncated DehydratedData command stream.");
    }

    private static ulong ReadFixup(MemoryImage memory, ulong fixups, int index) =>
        ReadRelativePointer(memory, checked(fixups + (ulong)index * 4));

    private static ulong ReadRelativePointer(MemoryImage memory, ulong field)
    {
        var delta = memory.ReadI32(field);
        return delta >= 0
            ? checked(field + (ulong)delta)
            : checked(field - (ulong)(-(long)delta));
    }

    private static int RelativeDelta(ulong target, ulong field)
    {
        var delta = (long)target - (long)field;
        if (delta is < int.MinValue or > int.MaxValue)
            throw new InvalidDataException("Relative relocation exceeds 32 bits.");
        return (int)delta;
    }

    private static void EnsureCapacity(
        MemoryImage memory, ulong destination, int written, int additional)
    {
        if (additional < 0 || !memory.Contains(checked(destination + (ulong)written), additional))
            throw new InvalidDataException("Hydrated output exceeds its mapped destination.");
    }

    private static void WriteI32(ArrayBufferWriter<byte> writer, int value)
    {
        var span = writer.GetSpan(4);
        BinaryPrimitives.WriteInt32LittleEndian(span, value);
        writer.Advance(4);
    }

    private static void WriteU64(ArrayBufferWriter<byte> writer, ulong value)
    {
        var span = writer.GetSpan(8);
        BinaryPrimitives.WriteUInt64LittleEndian(span, value);
        writer.Advance(8);
    }
}
