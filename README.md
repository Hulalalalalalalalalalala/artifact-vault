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

Objects are stored beneath `objects/` by SHA-256 digest. `index.json` maps logical names to immutable object metadata, and `snapshots/` holds one JSON record per snapshot. Writes use temporary files followed by rename so interrupted writes do not expose partial objects, indexes, or snapshots. All mutating operations (`init`, `put`, `snapshot create`, `snapshot restore`, `gc`) are serialized across processes with an `flock` on `<root>/.lock`, which is released automatically if a process dies mid-operation.

## Garbage collection

```bash
artifact-vault gc --root ./vault --dry-run
artifact-vault gc --root ./vault
```

`gc` deletes content objects that neither the current name mapping nor any saved snapshot still references — for example old versions left behind by overwritten uploads or objects orphaned by a snapshot restore. Objects referenced only by a snapshot (including snapshots with multi-level names) are kept. `--dry-run` deletes nothing and prints one `digest<TAB>size-in-bytes` line per candidate, sorted by digest, followed by a `total N objects, M bytes` summary; a real run prints `deleted N objects, M bytes`. Only regular files directly inside `objects/` whose names are valid digests are eligible; temp files, other names, subdirectories, and symlinks are left untouched, and the index and snapshots are never rewritten.

The pass runs under the exclusive repository lock, so it always observes a complete state and never collects an object while an upload, download, verify, or snapshot operation is in flight. Any unreadable or malformed reference (corrupt index or snapshot, invalid entry, snapshot name not matching its location, symlinks in `snapshots/`, an `objects/` path that is a symlink or unreadable) aborts the pass before anything is deleted. If a deletion fails mid-pass the command stops, reports the failed object and what was already deleted, and leaves the remaining candidates for the next run.
