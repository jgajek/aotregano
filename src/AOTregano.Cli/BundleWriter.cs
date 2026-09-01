using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AOTregano.Core;

namespace AOTregano.Cli;

internal static class BundleWriter
{
    private static readonly JsonSerializerOptions IndentedJson = new(AOTreganoJsonContext.Default.Options)
    {
        WriteIndented = true,
        TypeInfoResolver = AOTreganoJsonContext.Default
    };

    public static RunManifest Write(
        AOTreganoReport report,
        string inputSha256,
        long inputLength,
        string outputDirectory)
    {
        var directory = Directory.CreateDirectory(Path.GetFullPath(outputDirectory)).FullName;
        var outputs = new RunOutputs(
            Path.Combine(directory, "analysis.json"),
            Path.Combine(directory, "sections.json"),
            Path.Combine(directory, "method-tables.jsonl"),
            Path.Combine(directory, "strings.jsonl"),
            Path.Combine(directory, "arrays.jsonl"),
            Path.Combine(directory, "annotations.jsonl"),
            Path.Combine(directory, "mapped-image.bin"));

        var sections = report.Header.Sections.Select(section => new SectionRow(
            section.Type,
            section.Name,
            section.Flags,
            AddressValue.Of(section.Start),
            AddressValue.Of(section.End),
            section.Size)).ToArray();
        WriteJson(outputs.Sections, sections);

        var annotations = new List<AnnotationRow>();
        WriteJsonLines(outputs.MethodTables, report.MethodTables.Select(table =>
        {
            annotations.Add(new AnnotationRow(
                AddressValue.Of(table.Address), "methodTable", table.MethodTableName, null));
            return new MethodTableRow(
                AddressValue.Of(table.Address),
                table.Name,
                table.Layout,
                table.ElementType,
                RuntimeElementType.Prefix(table.ElementType),
                table.ComponentSize,
                table.Flags,
                table.BaseSize,
                AddressValue.Of(table.RelatedTypeAddress),
                table.VTableSlotCount,
                table.InterfaceCount,
                table.HashCode,
                table.VTable.Select(AddressValue.Of).ToArray(),
                table.InterfaceAddresses.Select(AddressValue.Of).ToArray());
        }), AOTreganoJsonContext.Default.MethodTableRow);

        WriteJsonLines(outputs.Strings, report.Strings.Select(value =>
        {
            annotations.Add(new AnnotationRow(
                AddressValue.Of(value.Address), "string", value.Name, value.Value));
            return new StringRow(AddressValue.Of(value.Address), value.Length, value.Name, value.Value);
        }), AOTreganoJsonContext.Default.StringRow);

        WriteJsonLines(outputs.Arrays, report.Arrays.Select(value =>
        {
            annotations.Add(new AnnotationRow(
                AddressValue.Of(value.Address), "array", value.Name, null));
            return new ArrayRow(AddressValue.Of(value.Address), value.Length, value.ElementType, value.Name);
        }), AOTreganoJsonContext.Default.ArrayRow);
        WriteJsonLines(outputs.Annotations, annotations, AOTreganoJsonContext.Default.AnnotationRow);
        AtomicWrite(outputs.MappedImage, report.Memory.ToArray());

        var integrityPaths = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Sections"] = outputs.Sections,
            ["MethodTables"] = outputs.MethodTables,
            ["Strings"] = outputs.Strings,
            ["Arrays"] = outputs.Arrays,
            ["Annotations"] = outputs.Annotations,
            ["MappedImage"] = outputs.MappedImage
        };
        var integrity = integrityPaths.ToDictionary(
            pair => pair.Key,
            pair => new IntegrityInfo(
                pair.Value,
                new FileInfo(pair.Value).Length,
                HashFile(pair.Value)),
            StringComparer.Ordinal);
        var bytesWritten = report.Hydration == HydrationState.Rehydrated
            ? report.PointerScan.End - report.PointerScan.Start
            : 0;
        var manifest = new RunManifest(
            RunManifest.Current,
            AOTreganoAnalyzer.Version,
            true,
            report.Image.Path,
            inputSha256,
            inputLength,
            report.Image.Format,
            report.Image.TargetOs,
            report.Image.Architecture,
            AddressValue.Of(report.Image.ImageBase),
            AddressValue.Of(report.Image.EntryPoint),
            report.Image.MappedSize,
            new RecognitionInfo(
                true,
                AddressValue.Of(report.Header.Address),
                report.Header.MajorVersion,
                report.Header.MinorVersion,
                report.Header.EntrySize,
                report.Header.EntryType,
                report.Header.Sections.Count),
            new HydrationInfo(
                report.Hydration == HydrationState.Rehydrated ? "rehydrated" : "notRequired",
                bytesWritten),
            new RecoveryCounts(
                report.PointerScan.Locations.Count,
                report.MethodTables.Count,
                report.Strings.Count,
                report.Arrays.Count,
                annotations.Count),
            outputs,
            integrity,
            [],
            report.Log,
            [
                "NativeAOT recovery reconstructs runtime structures and data; it cannot restore discarded IL, symbols, or source code.",
                "Synthetic type names are analysis identities, not original managed type names."
            ],
            [],
            false);
        AtomicWrite(outputs.Analysis, Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(manifest, IndentedJson) + Environment.NewLine));
        return manifest;
    }

    public static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private static void WriteJson(string path, IReadOnlyList<SectionRow> value) =>
        AtomicWrite(path, Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(value, IndentedJson) + Environment.NewLine));

    private static void WriteJsonLines<T>(
        string path,
        IEnumerable<T> values,
        System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> typeInfo)
    {
        var builder = new StringBuilder();
        foreach (var value in values)
            builder.AppendLine(JsonSerializer.Serialize(value, typeInfo));
        AtomicWrite(path, Encoding.UTF8.GetBytes(builder.ToString()));
    }

    private static void AtomicWrite(string path, byte[] value)
    {
        var fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        var staging = fullPath + $".{Environment.ProcessId}.tmp";
        try
        {
            File.WriteAllBytes(staging, value);
            File.Move(staging, fullPath, true);
        }
        finally
        {
            if (File.Exists(staging))
                File.Delete(staging);
        }
    }
}
