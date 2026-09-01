using System.Security.Cryptography;
using System.Text.Json.Nodes;
using AOTregano.Core;

namespace AOTregano.Mcp;

internal static class Tools
{
    public static JsonArray Listed() =>
    [
        new JsonObject
        {
            ["name"] = "analyze_nativeaot",
            ["description"] =
                "Statically rehydrate and recover an x64 .NET NativeAOT PE or ELF file. The input " +
                "is read as bytes and never loaded or executed. Returns recognition, hydration, " +
                "recovery counts, addresses, warnings, and the SHA-256. Use the CLI when the full " +
                "mapped image and JSONL artifact bundle should be written to disk.",
            ["inputSchema"] = new JsonObject
            {
                ["type"] = "object",
                ["additionalProperties"] = false,
                ["required"] = new JsonArray("path"),
                ["properties"] = new JsonObject
                {
                    ["path"] = new JsonObject
                    {
                        ["type"] = "string",
                        ["description"] = "Absolute or working-directory-relative path to the sample."
                    },
                    ["maxInputBytes"] = Limit("Maximum input size before parsing."),
                    ["maxMappedImageBytes"] = Limit("Maximum mapped-image allocation.")
                }
            }
        }
    ];

    public static JsonObject Call(JsonObject? parameters)
    {
        var name = parameters?["name"]?.GetValue<string>();
        if (name != "analyze_nativeaot")
            return Failed(name is null
                ? "A tool call must name analyze_nativeaot."
                : $"This server has no {name}.");
        var arguments = parameters?["arguments"] as JsonObject ?? [];
        return Analyze(arguments);
    }

    private static JsonObject Analyze(JsonObject arguments)
    {
        if (Word(arguments, "path") is not { } supplied)
            return Failed("analyze_nativeaot needs a path.");
        var path = Path.GetFullPath(supplied);
        if (Directory.Exists(path))
            return Failed($"That is a directory, not a file: {path}");
        if (!File.Exists(path))
            return Failed($"No such file: {path}");

        try
        {
            var maxInput = Positive(arguments, "maxInputBytes") ?? (1L << 30);
            var maxImage = Positive(arguments, "maxMappedImageBytes") ?? (1L << 30);
            var report = AOTreganoAnalyzer.Analyze(path, new ImageLimits(maxInput, maxImage));
            using var stream = File.OpenRead(path);
            var result = new JsonObject
            {
                ["schema"] = "aotregano.mcp.analysis/1",
                ["toolVersion"] = AOTreganoAnalyzer.Version,
                ["success"] = true,
                ["path"] = path,
                ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(stream)),
                ["format"] = report.Image.Format,
                ["targetOs"] = report.Image.TargetOs,
                ["architecture"] = report.Image.Architecture,
                ["imageBase"] = Hex(report.Image.ImageBase),
                ["entryPoint"] = Hex(report.Image.EntryPoint),
                ["readyToRun"] = new JsonObject
                {
                    ["address"] = Hex(report.Header.Address),
                    ["majorVersion"] = report.Header.MajorVersion,
                    ["minorVersion"] = report.Header.MinorVersion,
                    ["directoryEntrySize"] = report.Header.EntrySize,
                    ["sections"] = report.Header.Sections.Count
                },
                ["hydration"] = report.Hydration == HydrationState.Rehydrated
                    ? "rehydrated" : "notRequired",
                ["recovered"] = new JsonObject
                {
                    ["pointerCandidates"] = report.PointerScan.Locations.Count,
                    ["methodTables"] = report.MethodTables.Count,
                    ["strings"] = report.Strings.Count,
                    ["arrays"] = report.Arrays.Count
                },
                ["objectMethodTable"] = report.ObjectMethodTable is null
                    ? null : Hex(report.ObjectMethodTable.Address),
                ["stringMethodTable"] = report.StringMethodTable is null
                    ? null : Hex(report.StringMethodTable.Address),
                ["log"] = new JsonArray(
                    report.Log.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray()),
                ["limitations"] = new JsonArray(
                    "Recovery cannot restore discarded IL, original symbols, or source code.",
                    "Synthetic type names are analysis identities, not original managed names.")
            };
            return Said(result.ToJsonString());
        }
        catch (Exception exception) when (exception is
            UnsupportedImageException or ResourceLimitException or DehydrationException or
            RecoveryException or InvalidDataException or IOException or UnauthorizedAccessException or
            OverflowException)
        {
            return Failed(exception.Message);
        }
    }

    private static JsonObject Limit(string description) => new()
    {
        ["type"] = "integer",
        ["minimum"] = 1,
        ["description"] = description
    };

    private static string? Word(JsonObject value, string name) =>
        value[name] is JsonValue node && node.TryGetValue<string>(out var text) &&
        !string.IsNullOrWhiteSpace(text) ? text : null;

    private static long? Positive(JsonObject value, string name)
    {
        if (value[name] is null)
            return null;
        if (value[name] is JsonValue node && node.TryGetValue<long>(out var result) && result > 0)
            return result;
        throw new InvalidDataException($"{name} must be a positive integer.");
    }

    private static string Hex(ulong value) => $"0x{value:X}";

    private static JsonObject Said(string text) => new()
    {
        ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = text })
    };

    private static JsonObject Failed(string message) => new()
    {
        ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = message }),
        ["isError"] = true
    };
}
