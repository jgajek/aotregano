using System.Text;

namespace AOTregano.Core;

public static class RuntimeElementType
{
    public const int Boolean = 0x02;
    public const int Char = 0x03;
    public const int SByte = 0x04;
    public const int Byte = 0x05;
    public const int Int16 = 0x06;
    public const int UInt16 = 0x07;
    public const int Int32 = 0x08;
    public const int UInt32 = 0x09;
    public const int Int64 = 0x0A;
    public const int UInt64 = 0x0B;
    public const int IntPtr = 0x0C;
    public const int UIntPtr = 0x0D;
    public const int Single = 0x0E;
    public const int Double = 0x0F;
    public const int ValueType = 0x10;
    public const int Nullable = 0x12;
    public const int Class = 0x14;
    public const int Interface = 0x15;
    public const int Array = 0x17;
    public const int SzArray = 0x18;

    public static string Prefix(int type) => type switch
    {
        Class => "Class",
        ValueType => "Struct",
        Nullable => "Nullable",
        Interface => "IInterface",
        Array => "Array",
        SzArray => "SzArray",
        Boolean => "Enum_Boolean",
        Char => "Enum_Char",
        SByte => "Enum_SByte",
        Byte => "Enum_Byte",
        Int16 => "Enum_Int16",
        UInt16 => "Enum_UInt16",
        Int32 => "Enum_Int32",
        UInt32 => "Enum_UInt32",
        Int64 => "Enum_Int64",
        UInt64 => "Enum_UInt64",
        IntPtr => "Enum_IntPtr",
        UIntPtr => "Enum_UIntPtr",
        Single => "Enum_Single",
        Double => "Enum_Double",
        _ => "Type"
    };
}

public sealed class MethodTable
{
    public required ulong Address { get; init; }
    public required string Layout { get; init; }
    public required ushort ComponentSize { get; init; }
    public required uint Flags { get; init; }
    public required uint BaseSize { get; init; }
    public required ulong RelatedTypeAddress { get; init; }
    public required ushort VTableSlotCount { get; init; }
    public required ushort InterfaceCount { get; init; }
    public required uint HashCode { get; init; }
    public required IReadOnlyList<ulong> VTable { get; init; }
    public required IReadOnlyList<ulong> InterfaceAddresses { get; init; }
    public string Name { get; set; } = string.Empty;
    public MethodTable? RelatedType { get; set; }
    public List<MethodTable> Interfaces { get; } = [];
    public List<MethodTable> DerivedTypes { get; } = [];

    public int ElementType => Layout == "net70"
        ? (int)((Flags & 0xF800) >> 11)
        : (int)((Flags & 0x7C00_0000) >> 26);
    public bool IsInterface => ElementType == RuntimeElementType.Interface;
    public bool IsSzArray => ElementType == RuntimeElementType.SzArray;
    public string MethodTableName => $"{Name}_MT";
}

public sealed record RecoveredString(ulong Address, int Length, string Value, string Name);
public sealed record RecoveredArray(ulong Address, int Length, string ElementType, string Name);

internal sealed class MethodTableCrawler
{
    private const int MaximumSlots = 1000;
    private const int MaximumPasses = 100;
    private const ulong RelatedTypeOffset = 8;

    private readonly MemoryImage _memory;
    private readonly string _layout;
    private readonly PointerScan _pointers;
    private readonly ICollection<string> _log;
    private readonly Dictionary<ulong, MethodTable> _tables = [];

    public MethodTableCrawler(
        MemoryImage memory, string layout, PointerScan pointers, ICollection<string> log)
    {
        _memory = memory;
        _layout = layout;
        _pointers = pointers;
        _log = log;
    }

    public MethodTable? ObjectTable { get; private set; }
    public MethodTable? StringTable { get; private set; }
    public IReadOnlyDictionary<ulong, MethodTable> Tables => _tables;

    public void Analyze()
    {
        var candidates = FindObjectCandidates();
        if (candidates.Count != 1)
            throw new RecoveryException(
                $"Expected one System.Object candidate, found {candidates.Count}.");
        ObjectTable = ParseOrGet(candidates[0]);
        _log.Add($"Assuming 0x{ObjectTable.Address:X} is System.Object.");
        FindAllTables();
        StringTable = FindStringCandidate();
        AssignNames();
        _log.Add($"Recovered {_tables.Count} method tables.");
        if (StringTable is not null)
            _log.Add($"Assuming 0x{StringTable.Address:X} is System.String.");
    }

    private List<ulong> FindObjectCandidates()
    {
        var results = new SortedSet<ulong>();
        foreach (var location in _pointers.Locations)
        {
            try
            {
                if (location < 0x18 || !_memory.Contains(location, 32))
                    continue;
                var values = Enumerable.Range(0, 4)
                    .Select(index => _memory.ReadU64(location + (ulong)index * 8)).ToArray();
                if (!(LikelyCode(values[0]) && LikelyCode(values[1]) && LikelyCode(values[2]) &&
                      !LikelyCode(values[3])))
                    continue;
                if (_memory.ReadU16(location - 8) != 3 || _memory.ReadU16(location - 6) != 0 ||
                    _memory.ReadU64(location - 16) != 0)
                    continue;
                var expectedFlags = _layout == "net70" ? 0xA100_0000u : 0x5000_0000u;
                if (_memory.ReadU32(location - 24) != expectedFlags ||
                    _memory.ReadU32(location - 20) != 0x18)
                    continue;
                results.Add(location - 24);
            }
            catch (Exception exception) when (exception is InvalidDataException or OverflowException)
            {
            }
        }
        return [.. results];
    }

    private void FindAllTables()
    {
        var unmatched = _pointers.Locations.ToList();
        for (var pass = 1; pass < MaximumPasses; pass++)
        {
            var agenda = unmatched;
            unmatched = [];
            foreach (var location in agenda)
            {
                ulong relatedAddress;
                try
                {
                    relatedAddress = _memory.ReadU64(location);
                }
                catch (InvalidDataException)
                {
                    continue;
                }
                if (!_pointers.Contains(relatedAddress))
                    continue;
                if (!_tables.TryGetValue(relatedAddress, out var related))
                {
                    unmatched.Add(location);
                    continue;
                }
                if (location < RelatedTypeOffset)
                    continue;
                MethodTable table;
                try
                {
                    table = ParseOrGet(location - RelatedTypeOffset);
                }
                catch (Exception exception) when (exception is InvalidDataException or OverflowException)
                {
                    continue;
                }
                if (table.RelatedType is null && related.Address != table.Address)
                {
                    table.RelatedType = related;
                    if (!related.DerivedTypes.Contains(table))
                        related.DerivedTypes.Add(table);
                }
                foreach (var interfaceAddress in table.InterfaceAddresses.Where(value => value != 0))
                {
                    try
                    {
                        var interfaceTable = ParseOrGet(interfaceAddress);
                        if (!table.Interfaces.Contains(interfaceTable))
                            table.Interfaces.Add(interfaceTable);
                    }
                    catch (Exception exception) when (exception is InvalidDataException or OverflowException)
                    {
                    }
                }
            }
            if (unmatched.Count >= agenda.Count)
                break;
        }
    }

    private MethodTable? FindStringCandidate()
    {
        var candidates = _tables.Values.Where(table =>
            ReferenceEquals(table.RelatedType, ObjectTable) &&
            table.ElementType == RuntimeElementType.Class && table.BaseSize == 0x16).ToArray();
        return candidates.Length == 1 ? candidates[0] : null;
    }

    private MethodTable ParseOrGet(ulong address)
    {
        if (_tables.TryGetValue(address, out var existing))
            return existing;
        var table = ParseTable(address);
        table.Name = $"{RuntimeElementType.Prefix(table.ElementType)}_{address:X16}";
        _tables.Add(address, table);
        return table;
    }

    private MethodTable ParseTable(ulong address)
    {
        ushort componentSize;
        uint flags;
        if (_layout == "net70")
        {
            componentSize = _memory.ReadU16(address);
            flags = _memory.ReadU16(address + 2);
        }
        else
        {
            componentSize = 0;
            flags = _memory.ReadU32(address);
        }
        var baseSize = _memory.ReadU32(address + 4);
        var relatedType = _memory.ReadU64(address + 8);
        var slotCount = _memory.ReadU16(address + 16);
        var interfaceCount = _memory.ReadU16(address + 18);
        var hashCode = _memory.ReadU32(address + 20);
        if (slotCount >= MaximumSlots || interfaceCount >= MaximumSlots)
            throw new InvalidDataException("Invalid method-table slot count.");
        var cursor = address + 24;
        var vtable = Enumerable.Range(0, slotCount)
            .Select(index => _memory.ReadU64(cursor + (ulong)index * 8)).ToArray();
        cursor += (ulong)slotCount * 8;
        var interfaces = Enumerable.Range(0, interfaceCount)
            .Select(index => _memory.ReadU64(cursor + (ulong)index * 8)).ToArray();
        var table = new MethodTable
        {
            Address = address,
            Layout = _layout,
            ComponentSize = componentSize,
            Flags = flags,
            BaseSize = baseSize,
            RelatedTypeAddress = relatedType,
            VTableSlotCount = slotCount,
            InterfaceCount = interfaceCount,
            HashCode = hashCode,
            VTable = vtable,
            InterfaceAddresses = interfaces
        };
        if (table.IsInterface)
        {
            if (table.BaseSize != 0 || table.RelatedTypeAddress != 0)
                throw new InvalidDataException("Invalid interface method table.");
        }
        else if (table.BaseSize < 0x10)
        {
            throw new InvalidDataException("Invalid method-table base size.");
        }
        return table;
    }

    private void AssignNames()
    {
        if (ObjectTable is not null)
            ObjectTable.Name = "System_Object";
        if (StringTable is not null)
            StringTable.Name = "System_String";
    }

    private bool LikelyCode(ulong value) => value == 0 || _memory.IsExecutable(value);
}

internal static class FrozenObjectRecovery
{
    private const int MaximumLength = 0x10000;

    public static (IReadOnlyList<RecoveredString> Strings, IReadOnlyList<RecoveredArray> Arrays) Recover(
        MemoryImage memory,
        PointerScan pointers,
        ReadyToRunSection? frozenRegion,
        MethodTableCrawler crawler,
        ICollection<string> log)
    {
        if (frozenRegion is null || crawler.StringTable is null)
            return ([], []);
        var strings = new List<RecoveredString>();
        var arrays = new List<RecoveredArray>();
        var seenStrings = new HashSet<ulong>();
        var seenArrays = new HashSet<ulong>();
        foreach (var location in pointers.Locations)
        {
            if (location < frozenRegion.Start || location >= frozenRegion.End)
                continue;
            try
            {
                var methodTableAddress = memory.ReadU64(location);
                if (!crawler.Tables.TryGetValue(methodTableAddress, out var table))
                    continue;
                if (table.Address == crawler.StringTable.Address)
                {
                    var length = checked((int)memory.ReadU32(location + 8));
                    if (length > MaximumLength ||
                        !memory.Read(location + 12 + (ulong)length * 2, 2)
                            .SequenceEqual(new byte[] { 0, 0 }))
                        continue;
                    var value = Encoding.Unicode.GetString(memory.Read(location + 12, length * 2));
                    if (!seenStrings.Add(location))
                        continue;
                    var prefix = value.Length == 0 ? "Empty" : value[..Math.Min(value.Length, 32)];
                    strings.Add(new RecoveredString(
                        location, length, value, Sanitize($"dn_{prefix}_{location:X}", "dn")));
                    continue;
                }
                if (!table.IsSzArray)
                    continue;
                var arrayLength = checked((int)memory.ReadU32(location + 8));
                if (arrayLength > MaximumLength || !seenArrays.Add(location))
                    continue;
                var elementName = table.RelatedType?.Name ?? "Unknown";
                arrays.Add(new RecoveredArray(
                    location, arrayLength, elementName,
                    Sanitize($"{table.Name}_{location:X}", "array")));
            }
            catch (Exception exception) when (exception is InvalidDataException or OverflowException)
            {
            }
        }
        log.Add($"Recovered {strings.Count} frozen strings.");
        log.Add($"Recovered {arrays.Count} frozen arrays.");
        return (strings, arrays);
    }

    private static string Sanitize(string value, string fallback)
    {
        var result = new StringBuilder(Math.Min(value.Length, 200));
        var underscore = false;
        foreach (var character in value)
        {
            var accepted = char.IsAsciiLetterOrDigit(character) || character == '_';
            var next = accepted ? character : '_';
            if (next == '_' && underscore)
                continue;
            result.Append(next);
            underscore = next == '_';
            if (result.Length == 200)
                break;
        }
        var text = result.ToString();
        if (string.IsNullOrWhiteSpace(text.Trim('_')))
            text = fallback;
        if (char.IsDigit(text[0]))
            text = $"{fallback}_{text}";
        return text;
    }
}

public sealed class RecoveryException(string message) : Exception(message);
