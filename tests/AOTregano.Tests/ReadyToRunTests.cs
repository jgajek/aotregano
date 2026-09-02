using System.Buffers.Binary;
using AOTregano.Core;

namespace AOTregano.Tests;

public sealed class ReadyToRunTests
{
    private const ulong Base = 0x1800_0000_0;
    private const int HeaderRva = 0x100;

    [Fact]
    public void ParsesV18SixteenByteSizeAndStartEntry()
    {
        var start = Base + 0x500;
        var entry = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(entry, ReadyToRunSectionType.FrozenObjectRegion);
        BinaryPrimitives.WriteUInt32LittleEndian(entry.AsSpan(4), 0x80);
        BinaryPrimitives.WriteUInt64LittleEndian(entry.AsSpan(8), start);

        var header = ReadyToRunHeader.TryParse(Memory(entry, 16, 18), Base + HeaderRva);

        Assert.NotNull(header);
        Assert.Equal(16, header.EntrySize);
        Assert.Equal(start, header.Sections[0].Start);
        Assert.Equal(start + 0x80, header.Sections[0].End);
    }

    [Fact]
    public void PreservesLegacyTwentyFourByteStartAndEndEntry()
    {
        var start = Base + 0x500;
        var end = start + 0x80;
        var entry = new byte[24];
        BinaryPrimitives.WriteUInt32LittleEndian(entry, ReadyToRunSectionType.DehydratedData);
        BinaryPrimitives.WriteUInt32LittleEndian(entry.AsSpan(4), 3);
        BinaryPrimitives.WriteUInt64LittleEndian(entry.AsSpan(8), start);
        BinaryPrimitives.WriteUInt64LittleEndian(entry.AsSpan(16), end);

        var header = ReadyToRunHeader.TryParse(Memory(entry, 24, 9), Base + HeaderRva);

        Assert.NotNull(header);
        Assert.Equal(24, header.EntrySize);
        Assert.Equal(3u, header.Sections[0].Flags);
        Assert.Equal(end, header.Sections[0].End);
    }

    [Fact]
    public void RehydratesAllSixCommandTypes()
    {
        var bytes = new byte[0x1000];
        var memory = new MemoryImage(Base, bytes, [Section(bytes.Length)]);
        var source = Base + 0x100;
        var destination = Base + 0x500;
        var targetA = Base + 0x700;
        var targetB = Base + 0x780;
        var cursor = source;
        WriteI32(bytes, cursor, checked((int)(destination - cursor)));
        cursor += 4;
        bytes[Index(cursor++)] = (2 << 3) | MetadataRehydrator.Copy;
        bytes[Index(cursor++)] = (byte)'A';
        bytes[Index(cursor++)] = (byte)'B';
        bytes[Index(cursor++)] = (2 << 3) | MetadataRehydrator.ZeroFill;
        bytes[Index(cursor++)] = MetadataRehydrator.RelativePointerRelocation;
        bytes[Index(cursor++)] = (1 << 3) | MetadataRehydrator.PointerRelocation;
        bytes[Index(cursor++)] = (1 << 3) | MetadataRehydrator.InlineRelativePointerRelocation;
        WriteI32(bytes, cursor, checked((int)(targetA - cursor)));
        cursor += 4;
        bytes[Index(cursor++)] = (1 << 3) | MetadataRehydrator.InlinePointerRelocation;
        WriteI32(bytes, cursor, checked((int)(targetB - cursor)));
        cursor += 4;
        var commandEnd = cursor;
        WriteI32(bytes, cursor, checked((int)(targetA - cursor)));
        cursor += 4;
        WriteI32(bytes, cursor, checked((int)(targetB - cursor)));

        var result = MetadataRehydrator.Rehydrate(
            memory,
            new ReadyToRunSection(
                ReadyToRunSectionType.DehydratedData, 0, source, commandEnd));

        var expected = new byte[28];
        expected[0] = (byte)'A';
        expected[1] = (byte)'B';
        BinaryPrimitives.WriteInt32LittleEndian(
            expected.AsSpan(4), checked((int)(targetA - (destination + 4))));
        BinaryPrimitives.WriteUInt64LittleEndian(expected.AsSpan(8), targetB);
        BinaryPrimitives.WriteInt32LittleEndian(
            expected.AsSpan(16), checked((int)(targetA - (destination + 16))));
        BinaryPrimitives.WriteUInt64LittleEndian(expected.AsSpan(20), targetB);
        Assert.Equal(expected, memory.Read(destination, expected.Length).ToArray());
        Assert.Equal([destination + 8, destination + 20], result.Locations);
    }

    [Fact]
    public void RejectsCommandOperandThatCrossesTheDehydratedSection()
    {
        var bytes = new byte[0x1000];
        var memory = new MemoryImage(Base, bytes, [Section(bytes.Length)]);
        var source = Base + 0x100;
        var destination = Base + 0x500;
        WriteI32(bytes, source, checked((int)(destination - source)));
        bytes[Index(source + 4)] = (4 << 3) | MetadataRehydrator.Copy;

        Assert.Throws<InvalidDataException>(() => MetadataRehydrator.Rehydrate(
            memory,
            new ReadyToRunSection(
                ReadyToRunSectionType.DehydratedData, 0, source, source + 5)));
    }

    [Fact]
    public void RejectsRelocationOutputBeyondTheMappedImage()
    {
        var bytes = new byte[0x1000];
        var memory = new MemoryImage(Base, bytes, [Section(bytes.Length)]);
        var source = Base + 0x100;
        var destination = Base + (ulong)bytes.Length - 4;
        WriteI32(bytes, source, checked((int)(destination - source)));
        bytes[Index(source + 4)] = MetadataRehydrator.PointerRelocation;
        WriteI32(bytes, source + 5, checked((int)((Base + 0x700) - (source + 5))));

        Assert.Throws<InvalidDataException>(() => MetadataRehydrator.Rehydrate(
            memory,
            new ReadyToRunSection(
                ReadyToRunSectionType.DehydratedData, 0, source, source + 5)));
    }

    [Fact]
    public void LocatesOrphanedDirectoryAndRehydratesWithoutHeader()
    {
        var bytes = new byte[0x1000];
        var destination = Base + 0x700;
        var frozenStart = Base + 0x600;
        var source = Base + 0x300;
        var commandEnd = source + 7;
        var directory = Base + 0x100;
        WriteDirectoryEntry(bytes, directory, ReadyToRunSectionType.FrozenObjectRegion,
            frozenStart, frozenStart + 0x40);
        WriteDirectoryEntry(bytes, directory + 24, ReadyToRunSectionType.DehydratedData,
            source, commandEnd);
        WriteI32(bytes, source, checked((int)(destination - source)));
        bytes[Index(source + 4)] = (2 << 3) | MetadataRehydrator.Copy;
        bytes[Index(source + 5)] = (byte)'O';
        bytes[Index(source + 6)] = (byte)'K';
        var sections = new ImageSection[]
        {
            new(".rdata", 0, 0x700, 0, 0x700, 0x4000_0040),
            new("hydrated", 0x700, 0x100, 0, 0, 0xC000_0080)
        };
        var memory = new MemoryImage(Base, bytes, sections);

        var located = Assert.Single(OrphanedReadyToRunDirectory.Locate(memory));
        var dehydrated = Assert.Single(located.Sections.Where(section =>
            section.Type == ReadyToRunSectionType.DehydratedData));
        var result = MetadataRehydrator.Rehydrate(memory, dehydrated);

        Assert.Equal(directory, located.Address);
        Assert.Equal("OK"u8.ToArray(), memory.Read(destination, 2).ToArray());
        Assert.Equal(destination + 2, result.End);
    }

    [Fact]
    public void VaultRegressionWhenSampleIsAvailable()
    {
        var path = Environment.GetEnvironmentVariable("AOTREGANO_TEST_SAMPLE");
        if (string.IsNullOrWhiteSpace(path))
            return;

        var report = AOTreganoAnalyzer.Analyze(path);

        Assert.NotNull(report.Header);
        Assert.Equal(18, report.Header!.MajorVersion);
        Assert.Equal(5, report.Header.MinorVersion);
        Assert.Equal(16, report.Header.EntrySize);
        Assert.Equal(HydrationState.NotRequired, report.Hydration);
        Assert.Equal(2_157, report.MethodTables.Count);
        Assert.Equal(1_026, report.Strings.Count);
        Assert.Equal(31, report.Arrays.Count);
    }

    [Fact]
    public void OrphanedDirectoryVaultRegressionWhenSampleIsAvailable()
    {
        var path = Environment.GetEnvironmentVariable("AOTREGANO_TEST_ORPHANED_SAMPLE");
        if (string.IsNullOrWhiteSpace(path))
            return;

        var report = AOTreganoAnalyzer.Analyze(path);

        Assert.Null(report.Header);
        Assert.Equal("orphanedSectionDirectory", report.RecognitionSource);
        Assert.Equal("net80", report.MethodTableLayout);
        Assert.Equal(HydrationState.Rehydrated, report.Hydration);
        Assert.Equal(2_399, report.MethodTables.Count);
        Assert.Equal(1_163, report.Strings.Count);
        Assert.Equal(33, report.Arrays.Count);
    }

    private static MemoryImage Memory(byte[] entry, byte entrySize, ushort major)
    {
        var bytes = new byte[0x1000];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(HeaderRva), 0x0052_5452);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(HeaderRva + 4), major);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(HeaderRva + 6), 5);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(HeaderRva + 12), 1);
        bytes[HeaderRva + 14] = entrySize;
        bytes[HeaderRva + 15] = 1;
        entry.CopyTo(bytes, HeaderRva + 16);
        return new MemoryImage(Base, bytes, [Section(bytes.Length)]);
    }

    private static ImageSection Section(int size) =>
        new(".rdata", 0, (ulong)size, 0, (ulong)size, 0x4000_0040);

    private static int Index(ulong address) => checked((int)(address - Base));

    private static void WriteI32(byte[] bytes, ulong address, int value) =>
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(Index(address)), value);

    private static void WriteDirectoryEntry(
        byte[] bytes, ulong address, uint type, ulong start, ulong end)
    {
        var offset = Index(address);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), type);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 4), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset + 8), start);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset + 16), end);
    }
}
