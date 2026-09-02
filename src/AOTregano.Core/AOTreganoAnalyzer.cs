namespace AOTregano.Core;

public enum HydrationState
{
    NotRequired,
    Rehydrated
}

public sealed record AOTreganoReport(
    ExecutableImage Image,
    MemoryImage Memory,
    ReadyToRunHeader? Header,
    string RecognitionSource,
    ulong DirectoryAddress,
    IReadOnlyList<ReadyToRunSection> Sections,
    string MethodTableLayout,
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
    public const string Version = "0.2.0";

    public static AOTreganoReport Analyze(string path, ImageLimits? limits = null)
    {
        var log = new List<string>();
        var image = ExecutableImage.Open(path, limits);
        var memory = image.Map();
        log.Add(
            $"Loaded {image.TargetOs} {image.Format} image " +
            $"(base=0x{image.ImageBase:X}, entry=0x{image.EntryPoint:X}).");
        var headers = ReadyToRunHeader.Locate(memory);
        var header = headers.Count == 0 ? null : headers[0];
        IReadOnlyList<ReadyToRunSection> sections;
        string recognitionSource;
        ulong directoryAddress;
        if (header is not null)
        {
            sections = header.Sections;
            recognitionSource = "readyToRunHeader";
            directoryAddress = header.Address + 16;
            log.Add(
                $"Using ReadyToRun header at 0x{header.Address:X} " +
                $"(v{header.MajorVersion}.{header.MinorVersion}, entry size {header.EntrySize}).");
        }
        else
        {
            var orphanedDirectories = OrphanedReadyToRunDirectory.Locate(memory);
            var orphaned = orphanedDirectories.Count == 0
                ? throw new UnsupportedImageException(
                    "No supported ReadyToRun header or orphaned NativeAOT section directory was found.")
                : orphanedDirectories[0];
            sections = orphaned.Sections;
            recognitionSource = "orphanedSectionDirectory";
            directoryAddress = orphaned.Address;
            log.Add(
                $"Recovered orphaned NativeAOT section directory at 0x{orphaned.Address:X} " +
                $"({orphaned.Sections.Count} legacy entries; ReadyToRun header absent).");
        }

        var dehydrated = sections.FirstOrDefault(section =>
            section.Type == ReadyToRunSectionType.DehydratedData);
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

        var (crawler, layout) = AnalyzeMethodTables(
            memory,
            pointerScan,
            header is null ? ["net80", "net70"] :
                [header.MajorVersion <= 8 ? "net70" : "net80"],
            log);
        var (strings, arrays) = FrozenObjectRecovery.Recover(
            memory,
            pointerScan,
            sections.FirstOrDefault(section =>
                section.Type == ReadyToRunSectionType.FrozenObjectRegion),
            crawler,
            log);
        return new AOTreganoReport(
            image,
            memory,
            header,
            recognitionSource,
            directoryAddress,
            sections,
            layout,
            hydration,
            pointerScan,
            crawler.Tables.Values.OrderBy(table => table.Address).ToArray(),
            crawler.ObjectTable,
            crawler.StringTable,
            strings,
            arrays,
            log);
    }

    private static (MethodTableCrawler Crawler, string Layout) AnalyzeMethodTables(
        MemoryImage memory,
        PointerScan pointerScan,
        IReadOnlyList<string> layouts,
        List<string> log)
    {
        var failures = new List<string>();
        foreach (var layout in layouts)
        {
            var attemptLog = new List<string>();
            var crawler = new MethodTableCrawler(memory, layout, pointerScan, attemptLog);
            try
            {
                crawler.Analyze();
                foreach (var entry in attemptLog)
                    log.Add(entry);
                if (layouts.Count > 1)
                    log.Add($"Selected {layout} method-table layout by structural validation.");
                return (crawler, layout);
            }
            catch (RecoveryException exception)
            {
                failures.Add($"{layout}: {exception.Message}");
            }
        }
        throw new RecoveryException(
            $"No supported method-table layout matched ({string.Join("; ", failures)}).");
    }
}

public sealed class DehydrationException(string message, Exception innerException)
    : Exception(message, innerException);
