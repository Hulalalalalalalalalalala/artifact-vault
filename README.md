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

`put` stages the upload in a temporary file inside the repository while computing its size and SHA-256, then either installs it as a new content object or reuses the object already stored under the same digest. A successful put means the object behind the name's digest is verifiably complete: an existing object is reused only when it is a regular file whose full contents can be read and whose actual size and SHA-256 equal the upload's. A truncated or rewritten object (including a same-size object with different bytes), a symlink (followed or dangling), a directory, or an unreadable path fails the upload; the damaged object is never repaired by overwriting it, and the name mapping, existing objects, and snapshots are left unchanged, with the staged upload removed. Reuse never copies, rewrites, or re-permissions the healthy object, so any number of names — current or snapshot-only — can share one object. Errors name the upload, the digest, and the reason, distinguishing size mismatch, checksum mismatch, a non-regular-file path, and inspection or read failures.

`get` only delivers a file when the recorded name exists, the index and record are intact, and the stored object's actual size and SHA-256 match the record. The object is streamed and hashed into a temporary file beside the output; the output is replaced only after the complete, verified bytes are flushed, so a failed download leaves an existing output byte-for-byte unchanged and a missing output absent. Empty objects download normally, and large objects are streamed without buffering in memory.

The output must be safe: its parent directory must exist (it is never created), it must not be inside the repository — including a not-yet-created path or a path reached through a symlinked parent — and an existing output must be a regular file outside the repository that is not a hard link to any index, snapshot, lock, or content object. Symlinks, directories, and other non-regular files are refused. Errors distinguish a missing name, a corrupt record, a corrupt object, and an unsafe or unwritable output, and name the relevant artifact or output path. A download takes the shared repository lock, so it always observes one complete pre- or post-operation version and can never be interrupted mid-collection.

`verify` checks only the current name mapping: for every name in `index.json` it confirms the referenced object exists as a regular file and its actual size and SHA-256 match the record. Objects referenced solely by snapshots and unreferenced objects are never part of the result. On success it prints `verified N artifacts`, where N is the number of name records (two names pointing at one digest count as two); an empty repository verifies zero artifacts and a zero-byte artifact verifies normally. A missing object, a size or checksum mismatch, a non-regular-file path, or a read failure fails the command, names the artifact involved, and never prints the success line; the Go API returns a zero count on failure. Verify never rewrites the mapping, snapshots, or objects and never repairs damage.

The whole verify pass — from reading the mapping through the last object check — holds the shared repository lock continuously. Other read-only operations (`list`, `get`, and another `verify`) run concurrently with it, while `put`, `snapshot restore`, `snapshot import`, and `gc` wait for the pass to finish and vice versa. Verify therefore always certifies one complete, self-consistent state: if an overwrite, restore, or GC finished first, verify observes the finished mapping and its objects; if verify started first, that change completes only after verify ends — records and content from before and after a change can never be mixed. The lock is an `flock`, so this ordering also holds between separate processes that each opened the same repository, and a failed verify releases it just like a successful one.

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

The export output is held to the same safety rules as a `get` download, for both full and incremental packages (the command line and the Go API behave identically): the source repository must already exist and be initialized (export never creates one); the output must lie outside the source repository judged on actual locations — this covers paths that do not exist yet, a repository root specified through a symlink, and any symlinked parent that leads back into the repository, while a relative `..` path cannot escape the check and an unrelated directory sharing the repository's name prefix stays usable. The output's parent directory must already exist and be accessible (it is never created), although a symlinked parent that resolves to a normal directory outside the repository is fine. An existing output must be a regular file: symlinks (even dangling ones), directories, and other special files are refused and never replaced. A file outside the repository that is a hard link to the index, any snapshot record, the lock file, or any content object — including objects the exported snapshot does not reference — is also refused. The package is staged in the pinned parent directory and committed through its file descriptor, with the containment, file-type, and hard-link checks repeated immediately before the rename, so a parent replaced by a symlink to the repository during the export fails as an unsafe output and can never put the package on a repository file. Unsafe-output errors name the output path and the reason; missing/corrupt snapshots and missing/mismatching objects are still reported by snapshot name or object digest. On any failure the existing output (its contents and permissions), the repository's mapping, snapshots, objects, and lock are all left unchanged; an interrupted export leaves at most a temporary file, and retrying succeeds.

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
