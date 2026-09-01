using System.Text.Json;
using AOTregano.Core;

namespace AOTregano.Cli;

internal static class Program
{
    private sealed record Options(
        string Input,
        string OutputDirectory,
        bool Json,
        long MaximumInput,
        long MaximumImage);

    public static int Main(string[] args)
    {
        if (args.Contains("--version", StringComparer.Ordinal))
        {
            Console.WriteLine(AOTreganoAnalyzer.Version);
            return 0;
        }
        if (args.Length == 0 || args.Contains("--help", StringComparer.Ordinal) ||
            args.Contains("-h", StringComparer.Ordinal))
        {
            PrintHelp();
            return args.Length == 0 ? 2 : 0;
        }

        var wantsJson = args.Contains("--json", StringComparer.Ordinal);
        Options options;
        try
        {
            options = Parse(args);
        }
        catch (ArgumentException exception)
        {
            return Fail(wantsJson, "arguments", exception.Message, null, 2, false);
        }

        string? hash = null;
        long? length = null;
        try
        {
            var input = Path.GetFullPath(options.Input);
            var info = new FileInfo(input);
            if (!info.Exists)
                throw new FileNotFoundException("No such input file.", input);
            length = info.Length;
            hash = BundleWriter.HashFile(input);
            var report = AOTreganoAnalyzer.Analyze(
                input,
                new ImageLimits(options.MaximumInput, options.MaximumImage));
            var manifest = BundleWriter.Write(
                report,
                hash,
                length.Value,
                options.OutputDirectory);
            if (options.Json)
            {
                Console.WriteLine(JsonSerializer.Serialize(
                    manifest, AOTreganoJsonContext.Default.RunManifest));
            }
            else
            {
                PrintSummary(manifest);
            }
            return 0;
        }
        catch (FileNotFoundException exception)
        {
            return Fail(options.Json, "input", exception.Message, options.Input, 2, false, hash, length);
        }
        catch (UnsupportedImageException exception)
        {
            return Fail(options.Json, "unsupported", exception.Message, options.Input, 2, false, hash, length);
        }
        catch (ResourceLimitException exception)
        {
            return Fail(options.Json, "resourceLimit", exception.Message, options.Input, 2, true, hash, length);
        }
        catch (DehydrationException exception)
        {
            return Fail(options.Json, "hydrationFailed", exception.Message, options.Input, 1, false, hash, length);
        }
        catch (RecoveryException exception)
        {
            return Fail(options.Json, "recoveryIncomplete", exception.Message, options.Input, 1, false, hash, length);
        }
        catch (InvalidDataException exception)
        {
            return Fail(options.Json, "parse", exception.Message, options.Input, 2, false, hash, length);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or OverflowException)
        {
            return Fail(options.Json, "io", exception.Message, options.Input, 2, false, hash, length);
        }
    }

    private static Options Parse(string[] args)
    {
        string? input = null;
        string? output = null;
        var json = false;
        long maximumInput = 1L << 30;
        long maximumImage = 1L << 30;
        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];
            switch (argument)
            {
                case "--json":
                    json = true;
                    break;
                case "--output-dir":
                case "-o":
                    output = RequireValue(args, ref index, argument);
                    break;
                case "--max-input-size":
                    maximumInput = ParsePositive(RequireValue(args, ref index, argument), argument);
                    break;
                case "--max-image-size":
                    maximumImage = ParsePositive(RequireValue(args, ref index, argument), argument);
                    break;
                default:
                    if (argument.StartsWith('-'))
                        throw new ArgumentException($"Unknown option: {argument}");
                    if (input is not null)
                        throw new ArgumentException("Only one input file may be supplied.");
                    input = argument;
                    break;
            }
        }
        if (input is null)
            throw new ArgumentException("An input PE or ELF file is required.");
        var fullInput = Path.GetFullPath(input);
        output ??= Path.Combine(
            Path.GetDirectoryName(fullInput)!,
            "aotregano",
            Path.GetFileNameWithoutExtension(fullInput));
        return new Options(fullInput, Path.GetFullPath(output), json, maximumInput, maximumImage);
    }

    private static string RequireValue(string[] args, ref int index, string option)
    {
        if (++index >= args.Length || args[index].StartsWith('-'))
            throw new ArgumentException($"{option} requires a value.");
        return args[index];
    }

    private static long ParsePositive(string value, string option) =>
        long.TryParse(value, out var parsed) && parsed > 0
            ? parsed
            : throw new ArgumentException($"{option} requires a positive byte count.");

    private static int Fail(
        bool json,
        string kind,
        string message,
        string? input,
        int exitCode,
        bool moreWorkPossible,
        string? hash = null,
        long? length = null)
    {
        if (json)
        {
            var failure = new RunFailure(
                RunFailure.Current,
                AOTreganoAnalyzer.Version,
                false,
                kind,
                message,
                input is null ? null : Path.GetFullPath(input),
                hash,
                length,
                moreWorkPossible);
            Console.WriteLine(JsonSerializer.Serialize(
                failure, AOTreganoJsonContext.Default.RunFailure));
        }
        else
        {
            Console.Error.WriteLine($"AOTregano: {message}");
        }
        return exitCode;
    }

    private static void PrintSummary(RunManifest manifest)
    {
        Console.WriteLine($"File       {Path.GetFileName(manifest.InputPath)}");
        Console.WriteLine($"SHA-256    {manifest.InputSha256}");
        Console.WriteLine();
        Console.WriteLine(
            $"NativeAOT  ReadyToRun {manifest.Recognition.MajorVersion}." +
            $"{manifest.Recognition.MinorVersion}, " +
            $"{manifest.Recognition.DirectoryEntrySize}-byte directory entries");
        Console.WriteLine($"Hydration  {manifest.Hydration.State}");
        Console.WriteLine();
        Console.WriteLine($"Recovered  {manifest.Recovery.MethodTables:N0} method tables");
        Console.WriteLine($"           {manifest.Recovery.Strings:N0} frozen strings");
        Console.WriteLine($"           {manifest.Recovery.Arrays:N0} frozen arrays");
        Console.WriteLine();
        Console.WriteLine($"Wrote      {manifest.Wrote.Analysis}");
    }

    private static void PrintHelp()
    {
        Console.WriteLine("AOTregano - static recovery for .NET NativeAOT images");
        Console.WriteLine();
        Console.WriteLine("Usage: aotregano <input> [options]");
        Console.WriteLine();
        Console.WriteLine("  --json                    Write one machine-readable object to stdout");
        Console.WriteLine("  -o, --output-dir <path>   Recovery bundle directory");
        Console.WriteLine("  --max-input-size <bytes>  Input limit (default 1073741824)");
        Console.WriteLine("  --max-image-size <bytes>  Mapped-image limit (default 1073741824)");
        Console.WriteLine("  --version                 Print the tool version");
    }
}
