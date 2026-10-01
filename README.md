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
artifact-vault snapshot create --root ./vault --name v1
artifact-vault snapshot list --root ./vault
artifact-vault snapshot restore --root ./vault --name v1
```

Objects are stored beneath `objects/` by SHA-256 digest. `index.json` maps logical names to immutable object metadata. Writes use temporary files followed by rename so interrupted writes do not expose partial objects or indexes.

## Snapshots

A snapshot saves the name, digest, size, and creation time of every entry currently in the vault, without copying any object files. Creating a snapshot never blocks later puts: overwriting an artifact after a snapshot leaves the snapshot's records unchanged, and restoring brings back the saved mapping and original metadata.

- Snapshot names follow the same rules as logical artifact names (nonempty, relative, normalized).
- An empty vault can create a zero-entry snapshot; `snapshot list` prints `name<TAB>entry count` sorted by name and returns an empty list when none exist.
- Creating a snapshot with a missing/illegal/duplicate name, or restoring a missing snapshot, fails with a non-zero exit status and a recognizable reason.
- Restore validates every record (legal name, 64-character lowercase hex digest, non-negative size) and verifies that each referenced object's actual size and SHA-256 match the record. Any failure leaves the current mapping, other snapshots, and all objects untouched. Restore never reads the current index, so a vault with a corrupted `index.json` can still be restored from an intact snapshot.
- All mutating operations take an advisory flock on `.vault.lock`, so concurrent create/restore/put/init calls are serializable into a total order. The lock is released by the kernel if a process is killed. Snapshot and index files are written to temp files, fsynced, and atomically renamed into place, so an interrupted process leaves either the complete state or the previous state; stale temp files are ignored by `snapshot list` and cleaned up on the next create.
