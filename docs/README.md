# AOTregano analyst guide

AOTregano is a static-analysis tool for 64-bit .NET applications compiled with
NativeAOT. It reads a Windows PE or Linux ELF file as data, reconstructs selected
.NET runtime metadata, and writes artifacts that can be searched, scripted, or
imported into another analysis tool.

It does **not** run the sample, load it as a .NET assembly, call its exports, or
resolve libraries named by it.

This guide assumes familiarity with executable sections, virtual addresses,
pointers, strings, and basic static malware analysis. No detailed knowledge of
the .NET runtime is required.

## The short version

Normal .NET applications often contain Intermediate Language (IL) and rich
metadata that a .NET decompiler can use. NativeAOT applications are different:
their code is compiled ahead of time to native machine code. Much of the usual
managed metadata is absent, but the executable still needs runtime structures
that describe types and pre-created objects.

AOTregano recovers several of those structures:

- the NativeAOT/ReadyToRun section directory;
- metadata that the NativeAOT loader would normally rehydrate in memory;
- method tables, which are runtime descriptions of types;
- relationships between types, interfaces, and virtual method slots;
- frozen strings and one-dimensional, zero-based arrays;
- address-based annotations for use in later analysis.

The result is not source code and is not a replacement for a native-code
disassembler. It is a companion artifact that adds type-shaped landmarks and
readable data to an otherwise native binary.

## Small .NET glossary

| Term | Meaning in this guide |
| --- | --- |
| .NET | A software platform with a runtime and managed type system. C# is a common language used with it. |
| IL | Intermediate Language normally stored in many .NET assemblies. NativeAOT output generally does not retain the original IL needed by a decompiler. |
| NativeAOT | Ahead-of-time compilation of a .NET application into native machine code. |
| ReadyToRun | A family of runtime data formats. NativeAOT uses a ReadyToRun-style header and section directory to find internal data. |
| Method table | A runtime structure describing a managed type, including size, relationships, and virtual method slots. It is not just a list of methods. |
| Vtable | An ordered table of native function pointers used for virtual dispatch. |
| Frozen object | A managed object constructed at build time and stored in the executable image, such as a string or array. |
| Hydration | Expanding compact on-disk runtime metadata into the form expected in memory. It is unrelated to network access. |

## Supported input

| Property | Supported value |
| --- | --- |
| Operating system | Windows or Linux |
| Container | PE32+ or little-endian ELF64 |
| Architecture | AMD64/x64 |
| Runtime metadata | ReadyToRun/NativeAOT directory with 16-byte or 24-byte entries |
| Damaged header case | Selected binaries with a removed `RTR` header but a validated legacy section directory |

AOTregano is not a general PE/ELF repair tool, packer unpacker, memory-dump
carver, or .NET decompiler. Unsupported architectures and ordinary native
binaries are rejected.

## Quick start

Download the archive for the analysis host from the project release, extract it,
and keep the executable, `schema` directory, license, and README together.

Analyze one sample and choose an output directory:

```shell
aotregano suspicious.dll --output-dir recovery/suspicious
```

The terminal summary reports the sample hash, how NativeAOT was recognized,
whether hydration was needed, recovery counts, and the path to `analysis.json`.
The complete bundle is described in the [output reference](output-reference.md).

For a pipeline, add `--json`:

```shell
aotregano suspicious.dll --json --output-dir recovery/suspicious
```

On success, standard output contains exactly one `aotregano.run/2` JSON object.
On failure, it contains exactly one `aotregano.error/1` object. This makes it
safe to capture stdout without scraping human-readable messages.

If `--output-dir` is omitted, the default is an `aotregano/<sample-name>`
directory beside the input file.

## Command-line options

| Option | Meaning |
| --- | --- |
| `--json` | Emit one machine-readable result on stdout. |
| `-o`, `--output-dir <path>` | Set the recovery bundle directory. Existing named artifacts are replaced atomically. |
| `--max-input-size <bytes>` | Reject a file larger than this limit. Default: 1 GiB. |
| `--max-image-size <bytes>` | Reject a mapped image larger than this limit. Default: 1 GiB. |
| `--version` | Print the AOTregano version. |
| `-h`, `--help` | Print command help. |

The input and mapped-image limits are useful when processing untrusted samples
in automation. A small on-disk file can request a much larger virtual image, so
the limits are independent.

## Exit status

| Status | Meaning |
| --- | --- |
| `0` | Analysis and bundle creation completed. |
| `1` | NativeAOT was recognized, but hydration or recovery could not be completed. |
| `2` | Invalid arguments or input, unsupported format, parse/I/O failure, or resource limit. |

In JSON failure output, `ErrorKind` narrows the cause to `arguments`, `input`,
`unsupported`, `resourceLimit`, `hydrationFailed`, `recoveryIncomplete`, `parse`,
or `io`. `MoreWorkPossible` is currently true for a resource-limit failure and
false for other CLI failures.

## A practical analyst workflow

1. Record and independently verify the input SHA-256.
2. Run AOTregano in an isolated analysis environment.
3. Read `analysis.json` first. Confirm the format, image base, recognition source,
   hydration state, counts, limitations, and log.
4. Search `strings.jsonl` for configuration, URLs, paths, commands, and other
   indicators. Treat absence of a string as “not recovered,” not proof that the
   string is absent from the program.
5. Import or transform `annotations.jsonl` to label addresses in a disassembler.
6. Use `method-tables.jsonl` to investigate type relationships and vtable targets.
7. Consult `mapped-image.bin` when an address refers to reconstructed metadata.
   Convert a virtual address to a file position with
   `position = address - ImageBase`.
8. Verify every artifact against `ArtifactIntegrity` before moving it between
   systems or attaching it to a case.

All recovered artifacts remain derived from untrusted executable content.
Strings can contain terminal control characters, paths can be attacker chosen,
and the mapped image must never be treated as safe merely because AOTregano
created it.

## MCP server

`aotregano-mcp` exposes one stdio tool named `analyze_nativeaot`. It accepts a
local path and optional byte limits, then returns a compact recognition and
recovery summary. It never returns sample bytes and does not write the full
bundle. Use the CLI when durable artifacts are required.

Example client configuration:

```json
{
  "mcpServers": {
    "aotregano": {
      "command": "/path/to/aotregano-mcp"
    }
  }
}
```

## Read next

- [How recovery works](how-it-works.md)
- [Output reference](output-reference.md)
- [Machine-readable JSON schemas](../schema/README.md)
