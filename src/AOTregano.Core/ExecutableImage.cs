using System.Buffers.Binary;
using System.Text;

namespace AOTregano.Core;

public sealed record ImageLimits(long MaximumInputBytes, long MaximumMappedImageBytes)
{
    public static ImageLimits Default { get; } = new(1L << 30, 1L << 30);
}

public sealed record ImageSection(
    string Name,
    ulong VirtualAddress,
    ulong VirtualSize,
    ulong RawPointer,
    ulong RawSize,
    uint Characteristics)
{
    public ulong EndRva => checked(VirtualAddress + Math.Max(VirtualSize, RawSize));
    public bool IsExecutable => (Characteristics & 0x2000_0000) != 0;
    public bool IsInitialized => RawSize != 0;
}

public sealed class ExecutableImage
{
    private const ushort PeMachineAmd64 = 0x8664;
    private const ushort Pe32PlusMagic = 0x20B;
    private const ushort ElfMachineX64 = 0x3E;
    private const ulong ElfSectionAllocated = 0x02;
    private const ulong ElfSectionExecutable = 0x04;
    private const uint ElfSectionNoBits = 8;

    private readonly byte[] _file;

    private ExecutableImage(
        string path,
        ulong imageBase,
        ulong entryPoint,
        int mappedSize,
        string format,
        string targetOs,
        string architecture,
        IReadOnlyList<ImageSection> sections,
        byte[] file)
    {
        Path = path;
        ImageBase = imageBase;
        EntryPoint = entryPoint;
        MappedSize = mappedSize;
        Format = format;
        TargetOs = targetOs;
        Architecture = architecture;
        Sections = sections;
        _file = file;
    }

    public string Path { get; }
    public ulong ImageBase { get; }
    public ulong EntryPoint { get; }
    public int MappedSize { get; }
    public string Format { get; }
    public string TargetOs { get; }
    public string Architecture { get; }
    public IReadOnlyList<ImageSection> Sections { get; }

    public static ExecutableImage Open(string path, ImageLimits? limits = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = System.IO.Path.GetFullPath(path);
        var finalLimits = limits ?? ImageLimits.Default;
        var info = new FileInfo(fullPath);
        if (!info.Exists)
            throw new FileNotFoundException("No such input file.", fullPath);
        if (info.Length > finalLimits.MaximumInputBytes)
            throw new ResourceLimitException("Input exceeds the configured byte limit.");
        if (info.Length > int.MaxValue)
            throw new ResourceLimitException("Input is too large for this build.");

        var file = File.ReadAllBytes(fullPath);
        ExecutableImage image = file.AsSpan().StartsWith("\u007fELF"u8)
            ? ParseElf(fullPath, file)
            : ParsePe(fullPath, file);
        if (image.MappedSize > finalLimits.MaximumMappedImageBytes)
            throw new ResourceLimitException("Mapped image exceeds the configured byte limit.");
        return image;
    }

    public MemoryImage Map()
    {
        var mapped = new byte[MappedSize];
        foreach (var section in Sections)
        {
            if (section.RawSize == 0)
                continue;
            if (section.VirtualAddress > int.MaxValue || section.RawPointer > int.MaxValue ||
                section.RawSize > int.MaxValue)
                throw new InvalidDataException("Section cannot be represented by this build.");
            var destination = checked((int)section.VirtualAddress);
            var source = checked((int)section.RawPointer);
            var count = checked((int)section.RawSize);
            RequireRange(_file, source, count, "section raw data");
            RequireRange(mapped, destination, count, "mapped section");
            _file.AsSpan(source, count).CopyTo(mapped.AsSpan(destination, count));
        }
        return new MemoryImage(ImageBase, mapped, Sections);
    }

    private static ExecutableImage ParsePe(string path, byte[] file)
    {
        if (!file.AsSpan().StartsWith("MZ"u8))
            throw new UnsupportedImageException("Unsupported executable format.");
        RequireRange(file, 0x3C, 4, "DOS header");
        var peOffset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(0x3C, 4)));
        RequireRange(file, peOffset, 24, "PE header");
        if (!file.AsSpan(peOffset, 4).SequenceEqual("PE\0\0"u8))
            throw new InvalidDataException("Missing PE signature.");

        var fileHeader = peOffset + 4;
        var machine = ReadU16(file, fileHeader);
        if (machine != PeMachineAmd64)
            throw new UnsupportedImageException($"Unsupported PE machine 0x{machine:X4}.");
        var sectionCount = ReadU16(file, fileHeader + 2);
        var optionalSize = ReadU16(file, fileHeader + 16);
        if (sectionCount is 0 or > 96)
            throw new InvalidDataException("Invalid PE section count.");

        var optional = fileHeader + 20;
        RequireRange(file, optional, optionalSize, "PE optional header");
        var magic = ReadU16(file, optional);
        if (magic != Pe32PlusMagic)
            throw new UnsupportedImageException($"Unsupported PE optional-header magic 0x{magic:X4}.");
        var entryRva = ReadU32(file, optional + 0x10);
        var imageBase = ReadU64(file, optional + 0x18);
        var mappedSizeValue = ReadU32(file, optional + 0x38);
        if (mappedSizeValue == 0 || mappedSizeValue > int.MaxValue)
            throw new InvalidDataException("Invalid PE mapped-image size.");
        var mappedSize = (int)mappedSizeValue;

        var table = checked(optional + optionalSize);
        RequireRange(file, table, checked(sectionCount * 40), "PE section table");
        var sections = new List<ImageSection>(sectionCount);
        for (var index = 0; index < sectionCount; index++)
        {
            var offset = table + index * 40;
            var nameBytes = file.AsSpan(offset, 8);
            var terminator = nameBytes.IndexOf((byte)0);
            var name = Encoding.ASCII.GetString(terminator < 0 ? nameBytes : nameBytes[..terminator]);
            var virtualSize = ReadU32(file, offset + 8);
            var virtualAddress = ReadU32(file, offset + 12);
            var rawSize = ReadU32(file, offset + 16);
            var rawPointer = ReadU32(file, offset + 20);
            var characteristics = ReadU32(file, offset + 36);
            if ((ulong)virtualAddress + Math.Max(virtualSize, rawSize) > (ulong)mappedSize)
                throw new InvalidDataException($"Section {name} extends beyond the mapped image.");
            if (rawSize != 0)
                RequireRange(file, checked((int)rawPointer), checked((int)rawSize), $"section {name}");
            sections.Add(new ImageSection(
                name, virtualAddress, virtualSize, rawPointer, rawSize, characteristics));
        }

        return new ExecutableImage(
            path, imageBase, checked(imageBase + entryRva), mappedSize,
            "pe", "windows", "x64", sections, file);
    }

    private static ExecutableImage ParseElf(string path, byte[] file)
    {
        RequireRange(file, 0, 64, "ELF header");
        if (file[4] != 2 || file[5] != 1)
            throw new UnsupportedImageException("Only little-endian ELF64 images are supported.");
        var machine = ReadU16(file, 18);
        if (machine != ElfMachineX64)
            throw new UnsupportedImageException($"Unsupported ELF machine 0x{machine:X4}.");
        var entryPoint = ReadU64(file, 24);
        var sectionTable = ReadU64(file, 40);
        var sectionEntrySize = ReadU16(file, 58);
        var sectionCount = ReadU16(file, 60);
        var stringIndex = ReadU16(file, 62);
        if (sectionEntrySize < 64 || sectionCount == 0 || stringIndex >= sectionCount)
            throw new InvalidDataException("Invalid ELF section table.");
        var tableBytes = checked((ulong)sectionEntrySize * sectionCount);
        RequireRange(file, sectionTable, tableBytes, "ELF section table");

        var stringHeader = checked(sectionTable + (ulong)stringIndex * sectionEntrySize);
        var stringOffset = ReadU64(file, checked((int)stringHeader + 24));
        var stringSize = ReadU64(file, checked((int)stringHeader + 32));
        RequireRange(file, stringOffset, stringSize, "ELF section-name table");
        var strings = file.AsSpan(checked((int)stringOffset), checked((int)stringSize));

        var rawSections = new List<(string Name, uint Type, ulong Flags, ulong Address, ulong Offset, ulong Size)>();
        ulong minimum = ulong.MaxValue;
        ulong maximum = 0;
        for (var index = 0; index < sectionCount; index++)
        {
            var offset = checked((int)(sectionTable + (ulong)index * sectionEntrySize));
            var nameOffset = ReadU32(file, offset);
            var type = ReadU32(file, offset + 4);
            var flags = ReadU64(file, offset + 8);
            var address = ReadU64(file, offset + 16);
            var rawOffset = ReadU64(file, offset + 24);
            var size = ReadU64(file, offset + 32);
            if ((flags & ElfSectionAllocated) == 0)
                continue;
            if (nameOffset >= strings.Length)
                throw new InvalidDataException("Invalid ELF section name.");
            var nameSlice = strings[(int)nameOffset..];
            var end = nameSlice.IndexOf((byte)0);
            var name = Encoding.ASCII.GetString(end < 0 ? nameSlice : nameSlice[..end]);
            if (type != ElfSectionNoBits && size != 0)
                RequireRange(file, rawOffset, size, $"ELF section {name}");
            rawSections.Add((name, type, flags, address, rawOffset, size));
            minimum = Math.Min(minimum, address);
            maximum = Math.Max(maximum, checked(address + size));
        }
        if (minimum == ulong.MaxValue || maximum <= minimum || maximum - minimum > int.MaxValue)
            throw new InvalidDataException("Invalid ELF mapped-image range.");

        var sections = rawSections.Select(section => new ImageSection(
            section.Name,
            section.Address - minimum,
            section.Size,
            section.Type == ElfSectionNoBits ? 0 : section.Offset,
            section.Type == ElfSectionNoBits ? 0 : section.Size,
            (section.Flags & ElfSectionExecutable) != 0 ? 0x2000_0000u : 0u)).ToArray();
        return new ExecutableImage(
            path, minimum, entryPoint, checked((int)(maximum - minimum)),
            "elf", "linux", "x64", sections, file);
    }

    private static ushort ReadU16(byte[] data, int offset)
    {
        RequireRange(data, offset, 2, "16-bit field");
        return BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset, 2));
    }

    private static uint ReadU32(byte[] data, int offset)
    {
        RequireRange(data, offset, 4, "32-bit field");
        return BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
    }

    private static ulong ReadU64(byte[] data, int offset)
    {
        RequireRange(data, offset, 8, "64-bit field");
        return BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset, 8));
    }

    private static void RequireRange(byte[] data, int offset, int count, string field)
    {
        if (offset < 0 || count < 0 || offset > data.Length - count)
            throw new InvalidDataException($"Truncated or invalid {field}.");
    }

    private static void RequireRange(byte[] data, ulong offset, ulong count, string field)
    {
        if (offset > int.MaxValue || count > int.MaxValue || offset + count > (ulong)data.Length)
            throw new InvalidDataException($"Truncated or invalid {field}.");
    }
}

public sealed class MemoryImage
{
    private readonly byte[] _bytes;

    public MemoryImage(ulong imageBase, byte[] bytes, IReadOnlyList<ImageSection> sections)
    {
        ImageBase = imageBase;
        _bytes = bytes;
        Sections = sections;
    }

    public ulong ImageBase { get; }
    public IReadOnlyList<ImageSection> Sections { get; }
    public int Length => _bytes.Length;
    public ReadOnlySpan<byte> Bytes => _bytes;

    public bool Contains(ulong address, int count = 1)
    {
        if (count < 0 || address < ImageBase)
            return false;
        var offset = address - ImageBase;
        return offset <= (ulong)_bytes.Length && (ulong)count <= (ulong)_bytes.Length - offset;
    }

    public ImageSection? SectionAt(ulong address)
    {
        if (address < ImageBase)
            return null;
        var rva = address - ImageBase;
        return Sections.FirstOrDefault(section =>
            section.VirtualAddress <= rva && rva < section.EndRva);
    }

    public bool IsExecutable(ulong address) => SectionAt(address)?.IsExecutable == true;

    public ReadOnlySpan<byte> Read(ulong address, int count)
    {
        if (!Contains(address, count))
            throw new InvalidDataException($"Address 0x{address:X} is outside the mapped image.");
        return _bytes.AsSpan(checked((int)(address - ImageBase)), count);
    }

    public byte ReadU8(ulong address) => Read(address, 1)[0];
    public ushort ReadU16(ulong address) => BinaryPrimitives.ReadUInt16LittleEndian(Read(address, 2));
    public uint ReadU32(ulong address) => BinaryPrimitives.ReadUInt32LittleEndian(Read(address, 4));
    public int ReadI32(ulong address) => BinaryPrimitives.ReadInt32LittleEndian(Read(address, 4));
    public ulong ReadU64(ulong address) => BinaryPrimitives.ReadUInt64LittleEndian(Read(address, 8));

    public void Patch(ulong address, ReadOnlySpan<byte> value)
    {
        if (!Contains(address, value.Length))
            throw new InvalidDataException("Hydration destination is outside the mapped image.");
        value.CopyTo(_bytes.AsSpan(checked((int)(address - ImageBase)), value.Length));
    }

    public byte[] ToArray() => [.. _bytes];
}

public sealed class UnsupportedImageException(string message) : Exception(message);
public sealed class ResourceLimitException(string message) : Exception(message);
