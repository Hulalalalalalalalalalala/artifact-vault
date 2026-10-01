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

## Snapshots

Snapshots record the complete name mapping (name, digest, size, creation time of every entry) so the repository can be rolled back before overwriting artifacts. They reference the existing content objects; no artifact bytes are copied.

```bash
artifact-vault snapshot create --root ./vault --name before-release
artifact-vault snapshot list --root ./vault
artifact-vault snapshot restore --root ./vault --name before-release
```

`snapshot list` prints one `name<TAB>entry-count` line per snapshot, sorted by name. `snapshot restore` validates the record and re-checks every referenced object's size and SHA-256 before atomically replacing the current mapping; any failure leaves the current mapping and all snapshots unchanged. Restore works even when the current `index.json` is corrupted, as long as the snapshot and its objects are intact.

Objects are stored beneath `objects/` by SHA-256 digest. `index.json` maps logical names to immutable object metadata, and `snapshots/` holds one JSON record per snapshot. Writes use temporary files followed by rename so interrupted writes do not expose partial objects, indexes, or snapshots. All mutating operations (`init`, `put`, `snapshot create`, `snapshot restore`, `snapshot import`, `gc`) are serialized across processes with an `flock` on `<root>/.lock`, which is released automatically if a process dies mid-operation.

## Backup and migration

Snapshots can be exported to a single package file for backup or for moving to another machine. The package is a tar archive containing a `manifest.json` record and the referenced content objects under `objects/`.

```bash
artifact-vault snapshot export --root ./vault --name before-release --output ./package.tar
artifact-vault snapshot export --root ./vault --name before-release --output ./package.tar --base earlier-snapshot
artifact-vault snapshot import --root ./vault --file ./package.tar
```

`snapshot export` writes the target snapshot's complete mapping and every referenced object, each digest saved once. Every object referenced by the target — including ones omitted from an incremental package — is verified for existence, size, and SHA-256 before the package is written. A failure leaves any existing output file untouched.

With `--base`, the package still records the target snapshot's full mapping but only carries content not referenced by the named base snapshot. The base must already exist in the same repository. Name additions, overwrites, and disappearances are all based on the target mapping. An empty snapshot, an empty file, and two snapshots with identical content can all be exported.

`snapshot import` adds the package's snapshot to the target repository without replacing the current name mapping. A full package may be imported into an empty repository; an incremental package requires the target repository to already contain a base snapshot with the same name and identical entry metadata, and its referenced objects must be intact. Merely sharing a snapshot name or some digests is not a substitute for the exact base. Existing healthy objects with the same digest are reused; a corrupted object causes rejection. A snapshot with the same name and identical metadata is a no-op success; a same-name snapshot with different metadata is rejected.

Import rejects unknown package versions, illegal names or digests, negative sizes, duplicate entries, missing content, and checksum mismatches. Any failure leaves the current mapping, existing snapshots, and existing objects unchanged. After a write failure or process interruption, the new snapshot can only be fully recoverable or not yet appear; unreferenced complete objects may be left behind for a later `gc` to collect, and a retry can complete. The imported snapshot's referenced content is protected by the existing garbage collection.

Export prints `exported snapshot <name>: <entries> entries, <objects> objects`; import prints `imported snapshot <name>: <entries> entries, <added> objects added`.

## Garbage collection

```bash
artifact-vault gc --root ./vault --dry-run
artifact-vault gc --root ./vault
```

`gc` deletes content objects that neither the current name mapping nor any saved snapshot still references — for example old versions left behind by overwritten uploads or objects orphaned by a snapshot restore. Objects referenced only by a snapshot (including snapshots with multi-level names) are kept. `--dry-run` deletes nothing and prints one `digest<TAB>size-in-bytes` line per candidate, sorted by digest, followed by a `total N objects, M bytes` summary; a real run prints `deleted N objects, M bytes`. Only regular files directly inside `objects/` whose names are valid digests are eligible; temp files, other names, subdirectories, and symlinks are left untouched, and the index and snapshots are never rewritten.

The pass runs under the exclusive repository lock, so it always observes a complete state and never collects an object while an upload, download, verify, or snapshot operation is in flight. Any unreadable or malformed reference (corrupt index or snapshot, invalid entry, snapshot name not matching its location, symlinks in `snapshots/`, an `objects/` path that is a symlink or unreadable) aborts the pass before anything is deleted. If a deletion fails mid-pass the command stops, reports the failed object and what was already deleted, and leaves the remaining candidates for the next run.
