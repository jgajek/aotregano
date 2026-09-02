# AOTregano output reference

A successful CLI run creates one recovery directory containing seven files.
`analysis.json` is the index: start there, then follow its `Wrote` paths to the
other artifacts.

## Bundle at a glance

| File | Format | Purpose |
| --- | --- | --- |
| `analysis.json` | Indented JSON | Run manifest, provenance, counts, paths, hashes, log, and limitations. |
| `sections.json` | JSON array | NativeAOT/ReadyToRun directory entries. These are not the PE or ELF section table. |
| `method-tables.jsonl` | One JSON object per line | Recovered runtime type structures and relationships. |
| `strings.jsonl` | One JSON object per line | Recovered frozen UTF-16 strings. |
| `arrays.jsonl` | One JSON object per line | Recovered frozen array metadata. |
| `annotations.jsonl` | One JSON object per line | Flattened address/name records for downstream labeling. |
| `mapped-image.bin` | Raw bytes | The mapped virtual image after any metadata rehydration. |

JSON Lines (`.jsonl`) keeps large result sets streamable: process one line at a
time instead of loading the entire file. A file can validly be empty when no
records of that kind were recovered.

## Address representation

Manifest and artifact addresses use an object with the same value in two forms:

```json
{
  "Value": 140698833653760,
  "Hex": "0x7FF700001000"
}
```

`Value` is convenient for scripts and numeric comparisons. `Hex` is convenient
for analysts and disassemblers. Both are virtual addresses, not on-disk file
offsets.

## `analysis.json`

The success schema identifier is `aotregano.run/2`. Consumers should reject an
unknown schema major version and ignore unknown fields added within a known
major version.

### Provenance and image fields

| Field | Meaning |
| --- | --- |
| `Schema` | Output contract identifier. |
| `ToolVersion` | AOTregano executable version. |
| `Success` | Always `true` in this manifest. |
| `InputPath` | Absolute path used for the input. Do not use it as an evidence identifier. |
| `InputSha256` | Lowercase SHA-256 of the original on-disk sample. |
| `InputLength` | Original file length in bytes. |
| `Format` | `pe` or `elf`. |
| `TargetOs` | `windows` or `linux`. |
| `Architecture` | Currently always `x64`. |
| `ImageBase` | Lowest virtual address used for the mapped image. |
| `EntryPoint` | Executable entry-point virtual address. AOTregano records but never calls it. |
| `MappedImageLength` | Length of `mapped-image.bin`, including virtual padding. |

### `Recognition`

| Field | Meaning |
| --- | --- |
| `NativeAot` | Always `true` for a successful run. |
| `Source` | `readyToRunHeader` or `orphanedSectionDirectory`. |
| `ReadyToRunHeader` | Header virtual address, or `null` when the header was absent. |
| `Directory` | Virtual address of the first NativeAOT section-directory entry. |
| `MajorVersion`, `MinorVersion` | ReadyToRun version, or `null` for an orphaned directory. |
| `DirectoryEntrySize` | `16` or `24` bytes. Orphaned directories use `24`. |
| `DirectoryEntryType` | Currently `1`, or `null` when no header was available. |
| `Sections` | Number of validated directory entries. |

`orphanedSectionDirectory` means AOTregano recovered a validated directory after
failing to find a supported `RTR` header. It does not mean the whole executable
was repaired.

### `Hydration`

| Field | Meaning |
| --- | --- |
| `State` | `rehydrated` if AOTregano expanded `DehydratedData`; otherwise `notRequired`. |
| `BytesWritten` | Size of the reconstructed destination range. Zero when hydration was not required. |

Hydration modifies only `mapped-image.bin`, never the original input file.

### `Recovery`

| Field | Meaning |
| --- | --- |
| `PointerCandidates` | Pointer locations recorded by hydration or the manual aligned-pointer scan. |
| `MethodTables` | Validated method tables written to `method-tables.jsonl`. |
| `Strings` | Frozen strings written to `strings.jsonl`. |
| `Arrays` | Frozen array records written to `arrays.jsonl`. |
| `Annotations` | Total lines in `annotations.jsonl`. |

`PointerCandidates` can include values that are not semantically meaningful
pointers. The other counts are recovered through stronger structural checks.

### Paths, integrity, and messages

`Wrote` maps artifact names to their absolute output paths. `ArtifactIntegrity`
maps each data artifact to `Path`, byte `Length`, and lowercase `Sha256`.
`analysis.json` is omitted from `ArtifactIntegrity` because embedding its own
hash would be circular.

`Warnings`, `Limitations`, and `Blockers` distinguish non-fatal concerns,
inherent capability limits, and obstacles to further work. `Log` records major
recovery decisions, including the selected layout and inferred core method-table
addresses. `MoreWorkPossible` indicates whether changing conditions such as a
resource limit may allow a later run to proceed.

## `sections.json`

This file is a JSON array of NativeAOT section-directory records. It is **not**
a dump of PE sections such as `.text` or ELF sections such as `.rodata`.

| Field | Meaning |
| --- | --- |
| `Type` | Numeric ReadyToRun section type. |
| `Name` | Known symbolic name, `ReadonlyBlob_<type>`, or `Unknown_<type>`. |
| `Flags` | Directory-entry flags. Newer 16-byte entries report zero. |
| `Start`, `End` | Half-open virtual-address range `[Start, End)`. Zero-valued entries can represent an absent/empty region. |
| `Size` | `End - Start` when the range is valid. |

High-value records for this tool are `FrozenObjectRegion` (type 206) and
`DehydratedData` (type 207), although the complete validated directory is kept
for context.

## `method-tables.jsonl`

Each line describes one recovered method table.

| Field | Meaning |
| --- | --- |
| `Address` | Virtual address of the method table. |
| `Name` | `System_Object`, `System_String`, or a synthetic type identity. |
| `Layout` | Runtime structure interpretation selected by AOTregano: `net70` or `net80`. |
| `ElementType` | Numeric NativeAOT runtime element-type identifier. |
| `ElementTypeName` | Broad readable category such as `Class`, `Struct`, `IInterface`, or `SzArray`. |
| `ComponentSize` | Component-size field for layouts where AOTregano exposes it; otherwise zero. |
| `Flags` | Raw method-table flags under the selected layout. |
| `BaseSize` | Base allocation size recorded by the runtime structure. |
| `RelatedType` | Related method-table address, often a base type or array element type; can be zero. |
| `VTableSlotCount` | Number of entries in `VTable`. |
| `InterfaceCount` | Number of entries in `Interfaces`. |
| `HashCode` | Raw runtime type-hash field, not a cryptographic hash. |
| `VTable` | Virtual addresses of native method implementations. Zero entries are possible. |
| `Interfaces` | Method-table addresses for implemented interfaces. |

Do not read a name such as `Class_00007FF712345000` as an original class name.
It means only “class-shaped method table at this address.” Likewise, a vtable
target is an analysis lead, not proof of a particular managed method name.

## `strings.jsonl`

Each line has:

| Field | Meaning |
| --- | --- |
| `Address` | Virtual address of the frozen string object. |
| `Length` | Number of UTF-16 code units. |
| `Name` | Sanitized synthetic label derived from a short value prefix and address. |
| `Value` | Decoded string value. JSON escaping protects the file structure but does not make the text trusted. |

Only validated strings in the frozen-object region are included. This file is
not equivalent to a whole-file strings scan.

## `arrays.jsonl`

Each line has:

| Field | Meaning |
| --- | --- |
| `Address` | Virtual address of the frozen array object. |
| `Length` | Element count. |
| `ElementType` | Recovered or synthetic identity of the related element type. |
| `Name` | Synthetic label for the array. |

The current artifact describes array metadata; it does not serialize the array
elements.

## `annotations.jsonl`

This file flattens the most useful labels for import or conversion:

| Field | Meaning |
| --- | --- |
| `Address` | Virtual address to label. |
| `Kind` | `methodTable`, `string`, or `array`. |
| `Name` | Suggested synthetic label. |
| `Value` | String contents for string annotations; otherwise `null`. |

Analysts can transform these records into a Ghidra, IDA, Binary Ninja, or custom
database import format without joining the larger artifact files first.

## `mapped-image.bin`

This is a flat representation of the executable's mapped virtual address space.
File position zero corresponds to `ImageBase`; therefore:

```text
position in mapped-image.bin = virtual address - ImageBase
virtual address = ImageBase + position in mapped-image.bin
```

PE/ELF raw file offsets do not apply to this artifact. Section bytes appear at
their virtual positions, uninitialized space is zero-filled, and a successful
hydration is patched into its destination range. The image contains no loader
state beyond what AOTregano reconstructs and should not be assumed runnable.
Never execute it.

## JSON failure output

With `--json`, a failed run emits an `aotregano.error/1` object and does not
create a successful manifest. Its fields are:

| Field | Meaning |
| --- | --- |
| `Schema` | `aotregano.error/1`. |
| `ToolVersion` | AOTregano version. |
| `Success` | Always `false`. |
| `ErrorKind` | Stable category for programmatic handling. |
| `Error` | Human-readable detail. Do not build automation around the exact wording. |
| `InputPath` | Absolute input path when one was available; otherwise `null`. |
| `InputSha256` | Input hash when hashing completed; otherwise `null`. |
| `InputLength` | Input size when known; otherwise `null`. |
| `MoreWorkPossible` | Whether a changed condition may permit another attempt. |

The authoritative machine-readable definitions are
[`run.schema.json`](../schema/run.schema.json) and
[`error.schema.json`](../schema/error.schema.json).
