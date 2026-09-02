# AOTregano

Static recovery and rehydration for .NET NativeAOT binaries, without executing them.

AOTregano reads a PE or ELF image as data, locates its ReadyToRun directory,
rehydrates NativeAOT metadata where required, and recovers analysis artifacts
such as method tables, frozen strings, and frozen arrays. It never loads the
sample as an assembly or invokes its code.

When a protector or post-processor removes the `RTR` header but leaves the
NativeAOT section directory, AOTregano can recover that orphaned directory by
validating its ordered entries, mapped address ranges, frozen-object region,
dehydration stream, and zero-raw `hydrated` destination.

> This project is under active development. Recovered images remain untrusted
> executable content and must be handled like the original sample.

## Build

The current development target is .NET 9:

```shell
dotnet restore AOTregano.slnx
dotnet build AOTregano.slnx -c Release --no-restore
dotnet test AOTregano.slnx -c Release --no-restore --no-build
```

## Use

```shell
aotregano suspicious.dll --json --output-dir recovery
```

Human-readable output is the default. `--json` writes exactly one versioned
JSON object to standard output for pipelines. The output directory contains a
mapped image plus JSON/JSONL recovery artifacts named by the run manifest.

Exit status is `0` for a complete run, `1` when NativeAOT was recognized but
recovery could not be completed, and `2` for invalid input, unsupported images,
resource limits, or I/O errors. In `--json` mode failures are also exactly one
versioned JSON object on standard output; diagnostics never contaminate it.

The current image support is PE32+ AMD64 and little-endian ELF64 AMD64. Both
legacy 24-byte ReadyToRun directory entries (including validated orphaned
directories) and the 16-byte size/start entries used by ReadyToRun 18 are
understood. When `DehydratedData` is present,
AOTregano implements all six NativeAOT hydration commands. When it is absent,
the manifest explicitly reports `notRequired` rather than claiming a hydration.

## MCP

`aotregano-mcp` exposes `analyze_nativeaot` over stdio MCP. It returns a compact
recognition and recovery result suited to an agent's context window, and never
returns sample bytes. Configure a client with the executable as the MCP command:

```json
{
  "mcpServers": {
    "aotregano": { "command": "/path/to/aotregano-mcp" }
  }
}
```

Use the CLI for a durable bundle: `analysis.json`, the mapped image, ReadyToRun
sections, method tables, strings, arrays, annotations, and a SHA-256 for every
artifact. Schemas live in [`schema`](schema).

## Output compatibility

The top-level `Schema` field identifies the contract. Consumers should reject an
unknown major version and ignore unknown properties within a known major
version. Address objects contain both an unsigned numeric `Value` and a `Hex`
rendering so callers do not have to infer number formatting.

## Safety boundary

- Input files are parsed as bytes and are never executed.
- AOTregano does not use `Assembly.Load`, invoke exports, or resolve native
  libraries named by the sample.
- Resource limits are applied before the mapped image is allocated.
- Recovery reconstructs runtime structures; it cannot restore discarded IL,
  original symbols, or source code.
- Output files still describe or contain untrusted executable content. AOTregano
  never launches them, and callers should preserve that boundary.

## License

MIT
