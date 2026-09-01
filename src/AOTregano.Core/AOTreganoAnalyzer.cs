namespace AOTregano.Core;

public enum HydrationState
{
    NotRequired,
    Rehydrated
}

public sealed record AOTreganoReport(
    ExecutableImage Image,
    MemoryImage Memory,
    ReadyToRunHeader Header,
    HydrationState Hydration,
    PointerScan PointerScan,
    IReadOnlyList<MethodTable> MethodTables,
    MethodTable? ObjectMethodTable,
    MethodTable? StringMethodTable,
    IReadOnlyList<RecoveredString> Strings,
    IReadOnlyList<RecoveredArray> Arrays,
    IReadOnlyList<string> Log);

public static class AOTreganoAnalyzer
{
    public const string Version = "0.1.0";

    public static AOTreganoReport Analyze(string path, ImageLimits? limits = null)
    {
        var log = new List<string>();
        var image = ExecutableImage.Open(path, limits);
        var memory = image.Map();
        log.Add(
            $"Loaded {image.TargetOs} {image.Format} image " +
            $"(base=0x{image.ImageBase:X}, entry=0x{image.EntryPoint:X}).");
        var header = ReadyToRunHeader.Locate(memory).FirstOrDefault()
            ?? throw new UnsupportedImageException(
                "No supported ReadyToRun directory was found.");
        log.Add(
            $"Using ReadyToRun header at 0x{header.Address:X} " +
            $"(v{header.MajorVersion}.{header.MinorVersion}, entry size {header.EntrySize}).");

        var dehydrated = header.GetSection(ReadyToRunSectionType.DehydratedData);
        PointerScan pointerScan;
        HydrationState hydration;
        if (dehydrated is { Size: > 0 })
        {
            try
            {
                pointerScan = MetadataRehydrator.Rehydrate(memory, dehydrated, log);
                hydration = HydrationState.Rehydrated;
            }
            catch (Exception exception) when (
                exception is InvalidDataException or OverflowException or ResourceLimitException)
            {
                throw new DehydrationException(
                    $"DehydratedData was present but could not be reconstructed: {exception.Message}",
                    exception);
            }
        }
        else
        {
            pointerScan = MetadataRehydrator.ScanPointers(memory, log);
            hydration = HydrationState.NotRequired;
        }

        var layout = header.MajorVersion <= 8 ? "net70" : "net80";
        var crawler = new MethodTableCrawler(memory, layout, pointerScan, log);
        crawler.Analyze();
        var (strings, arrays) = FrozenObjectRecovery.Recover(
            memory,
            pointerScan,
            header.GetSection(ReadyToRunSectionType.FrozenObjectRegion),
            crawler,
            log);
        return new AOTreganoReport(
            image,
            memory,
            header,
            hydration,
            pointerScan,
            crawler.Tables.Values.OrderBy(table => table.Address).ToArray(),
            crawler.ObjectTable,
            crawler.StringTable,
            strings,
            arrays,
            log);
    }
}

public sealed class DehydrationException(string message, Exception innerException)
    : Exception(message, innerException);
