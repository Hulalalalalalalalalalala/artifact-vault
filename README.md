# Artifact Vault

Artifact Vault is a small Go command-line service for storing named files by content digest. It is the initial product baseline for a file and artifact storage system.

## Build and test

```bash
go test ./...
go build ./cmd/artifact-vault
```

## Usage

```bash
artifact-vault init --root ./vault
artifact-vault put --root ./vault --name releases/app.bin --file ./app.bin
artifact-vault list --root ./vault
artifact-vault get --root ./vault --name releases/app.bin --output ./restored.bin
artifact-vault verify --root ./vault
```

## Safe downloads

`get` only delivers a file once the complete name record **and** the complete object content have been verified. Before anything is written it checks the current index and the selected entry: the index must parse and carry a name mapping, the entry must be filed under its own name with a 64-character lowercase-hex SHA-256 digest and a non-negative size. The object must exist, be a regular file (never a symbolic link), and its actual size and SHA-256 must match the record. Empty objects download as empty files. Failures fall into four distinct classes, each naming the artifact or output path: name not found, a corrupted record, a corrupted/missing object, and an unusable output target.

The verified bytes are streamed to a temporary file in the output directory (memory use stays constant regardless of object size) and published with a single atomic rename. Consequently an existing output file keeps its exact bytes after any failure — it is never truncated first — and when the output does not exist no half-written file ever occupies its name; a crash leaves at most an unpublished `.download-*` temp file, and the next `get` completes without manual cleanup. The delivered file keeps the previous file's permission bits (new files are created `0644`).

Output safety rules:

- the parent directory must already exist (no directories are created);
- an existing output that is a directory, symbolic link, or other non-regular file is refused;
- no path inside the repository is accepted, including paths that do not exist yet and paths that enter the repository through a symbolic link in a parent directory;
- an existing destination outside the repository is refused when it is a hard link to `index.json`, `.lock`, a snapshot record, or a content object, so replacing it cannot modify a repository file;
- ordinary paths outside the repository continue to be created or overwritten.

A download holds the shared repository lock and never modifies the index, snapshots, or content objects, so a concurrent `put`, snapshot restore, or garbage collection can only make it observe the complete before- or after-version of one record and object — never a mix, and never an object collected mid-download.


## Snapshots

Snapshots record the complete name mapping (name, digest, size, creation time of every entry) so the repository can be rolled back before overwriting artifacts. They reference the existing content objects; no artifact bytes are copied.

```bash
artifact-vault snapshot create --root ./vault --name before-release
artifact-vault snapshot list --root ./vault
artifact-vault snapshot restore --root ./vault --name before-release
```

`snapshot list` prints one `name<TAB>entry-count` line per snapshot, sorted by name. `snapshot restore` validates the record and re-checks every referenced object's size and SHA-256 before atomically replacing the current mapping; any failure leaves the current mapping and all snapshots unchanged. Restore works even when the current `index.json` is corrupted, as long as the snapshot and its objects are intact.

## Moving snapshots to another machine

A snapshot package carries one complete snapshot, together with the content objects it needs, so it can be copied to and restored from a different repository.

```bash
artifact-vault snapshot export --root ./vault --name before-release --output ./before-release.vaultpkg
artifact-vault snapshot export --root ./vault --name after-release --base before-release --output ./after-release.vaultpkg
artifact-vault snapshot import --root ./other-vault --file ./before-release.vaultpkg
artifact-vault snapshot restore --root ./other-vault --name before-release
```

The destination repository must already be initialized. `snapshot export` writes a portable package (`--output`, atomically) containing the target snapshot's full entry metadata; a digest shared by several entries is carried once. Export re-verifies the size and SHA-256 of every object the snapshot references and never leaves a partial output file behind on failure.

With `--base <snapshot>` the package is incremental: it still records the target snapshot's complete mapping but only carries objects the base snapshot does not reference. Importing such a package requires the destination to already contain a snapshot with the base name and byte-identical entry metadata, with every omitted object present and intact; a same-named snapshot with different metadata, or objects that merely happen to share digests, is not a substitute for the base. A package without a base is self-contained and can be imported into an empty repository.

Import only adds the package's snapshot and any missing objects; it never changes the current name mapping or any existing snapshot or object. Healthy objects already present in the destination (including in an empty target initialized first) are reused; re-importing a package whose snapshot is already present with identical metadata succeeds without adding another copy, while a same-named snapshot with different metadata is refused. Afterwards `snapshot restore` applies the imported mapping, and imported content is protected from `gc` exactly like any snapshot-referenced object. On any failure — unknown package version, illegal names or digests, negative sizes, duplicate entries, missing or mismatching content, or a damaged destination object — the current mapping, existing snapshots, and existing objects are left untouched; an interrupted import leaves at most unreferenced complete objects that the next `gc` clears and a retry completes.

Export prints `exported snapshot <name> with <entries> entries, <objects> objects`; import prints `imported snapshot <name> with <entries> entries, <new-objects> new objects`.

Objects are stored beneath `objects/` by SHA-256 digest. `index.json` maps logical names to immutable object metadata, and `snapshots/` holds one JSON record per snapshot. Writes use temporary files followed by rename so interrupted writes do not expose partial objects, indexes, or snapshots. All mutating operations (`init`, `put`, `snapshot create`, `snapshot restore`, `snapshot import`, `gc`) are serialized across processes with an `flock` on `<root>/.lock`, which is released automatically if a process dies mid-operation. `snapshot export` also takes the exclusive lock so the verified snapshot and its objects cannot change or be collected mid-export.

## Garbage collection

```bash
artifact-vault gc --root ./vault --dry-run
artifact-vault gc --root ./vault
```

`gc` deletes content objects that neither the current name mapping nor any saved snapshot still references — for example old versions left behind by overwritten uploads or objects orphaned by a snapshot restore. Objects referenced only by a snapshot (including snapshots with multi-level names) are kept. `--dry-run` deletes nothing and prints one `digest<TAB>size-in-bytes` line per candidate, sorted by digest, followed by a `total N objects, M bytes` summary; a real run prints `deleted N objects, M bytes`. Only regular files directly inside `objects/` whose names are valid digests are eligible; temp files, other names, subdirectories, and symlinks are left untouched, and the index and snapshots are never rewritten.

The pass runs under the exclusive repository lock, so it always observes a complete state and never collects an object while an upload, download, verify, or snapshot operation is in flight. Any unreadable or malformed reference (corrupt index or snapshot, invalid entry, snapshot name not matching its location, symlinks in `snapshots/`, an `objects/` path that is a symlink or unreadable) aborts the pass before anything is deleted. If a deletion fails mid-pass the command stops, reports the failed object and what was already deleted, and leaves the remaining candidates for the next run.
