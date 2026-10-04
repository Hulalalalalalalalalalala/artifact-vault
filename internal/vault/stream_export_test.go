package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"
)

func stdBase64(content []byte) string {
	return base64.StdEncoding.EncodeToString(content)
}

func sortedStringSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// zeroReader yields an arbitrary number of zero bytes from a fixed zero
// backing array, so it allocates nothing proportional to the bytes produced.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func digestOfN(n int64) string {
	h := sha256.New()
	if _, err := io.CopyBuffer(h, io.LimitReader(zeroReader{}, n), make([]byte, 32*1024)); err != nil {
		panic(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// memSource builds a streaming object source over in-memory content.
func memSource(digest string, content []byte) packageObjectSource {
	return packageObjectSource{
		digest: digest,
		size:   int64(len(content)),
		open:   func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(content)), nil },
	}
}

// byteContents returns deterministic payloads whose lengths span base64
// padding boundaries (mod 3) and the 32KiB streaming buffer boundary.
func byteContents() map[string][]byte {
	sizes := []int{
		0, 1, 2, 3, 4, 5, 6,
		32*1024 - 2, 32*1024 - 1, 32 * 1024, 32*1024 + 1, 32*1024 + 2,
		64*1024 + 5,
	}
	out := map[string][]byte{}
	for _, n := range sizes {
		content := make([]byte, n)
		for i := range content {
			content[i] = byte((i*7 + 3) % 256) // arbitrary, includes every byte
		}
		out[sha256Hex(content)] = content
	}
	return out
}

func sha256Hex(content []byte) string {
	return digestOf(string(content))
}

// TestStreamingPackageIsByteIdenticalToMarshalPackage pins the core
// compatibility guarantee: the streaming serializer must emit exactly the
// document the old in-memory marshalPackage emitted, for full and delta
// packages and across object counts, empty payloads, and buffer boundaries.
func TestStreamingPackageIsByteIdenticalToMarshalPackage(t *testing.T) {
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	contents := byteContents()
	digests := make([]string, 0, len(contents))
	for d := range contents {
		digests = append(digests, d)
	}
	sort.Strings(digests)

	snap := Snapshot{Name: "snap/name", Entries: map[string]Entry{}}
	baseSnap := Snapshot{Name: "base/name", Entries: map[string]Entry{}}
	// Share one digest between two target entries and include a name with
	// characters the JSON encoder escapes, to exercise metadata rendering.
	snap.Entries["zeta & co"] = Entry{Name: "zeta & co", Digest: digests[0], Size: int64(len(contents[digests[0]])), CreatedAt: stamp}
	snap.Entries["alpha"] = Entry{Name: "alpha", Digest: digests[0], Size: int64(len(contents[digests[0]])), CreatedAt: stamp}
	for i, d := range digests {
		if i == 0 {
			continue
		}
		n := "n" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))
		snap.Entries[n] = Entry{Name: n, Digest: d, Size: int64(len(contents[d])), CreatedAt: stamp}
	}
	baseSnap.Entries["only-in-base"] = Entry{Name: "only-in-base", Digest: digests[1], Size: int64(len(contents[digests[1]])), CreatedAt: stamp}

	cases := []struct {
		name    string
		base    *Snapshot
		indexes []int // which digests the package carries
	}{
		{"empty objects", nil, []int{}},
		{"single zero byte", nil, []int{0}},
		{"several objects", nil, []int{0, 1, 2, 3, 4}},
		{"all objects", nil, allIndexes(len(digests))},
		{"delta with objects", &baseSnap, []int{2, 3, 5, len(digests) - 1}},
		{"delta with no objects", &baseSnap, []int{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sources := make([]packageObjectSource, 0, len(tc.indexes))
			objs := []PackageObject{}
			for _, i := range tc.indexes {
				d := digests[i]
				content := contents[d]
				sources = append(sources, memSource(d, content))
				objs = append(objs, PackageObject{
					Digest: d,
					Size:   int64(len(content)),
					Data:   stdBase64(content),
				})
			}
			old := &Package{
				Format:   packageFormat,
				Version:  packageVersion,
				Snapshot: snap,
				Base:     tc.base,
				Objects:  objs,
			}
			want, err := marshalPackage(old)
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			if err := writeStreamingPackage(&got, snap, tc.base, sources); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("streaming package differs from marshalPackage\nwant:\n%s\ngot:\n%s", want, got.String())
			}
		})
	}
}

func allIndexes(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

// TestExportedFileIsByteIdenticalToOldFormat builds a real package through the
// refactored export and re-derives the exact bytes the old in-memory path
// would have produced from the same repository, then compares them.
func TestExportedFileIsByteIdenticalToOldFormat(t *testing.T) {
	src, _ := seedVault(t, map[string]string{
		"releases/app.txt": "version one\n",
		"docs/readme.txt":  "version one\n", // shared digest, carried once
		"empty.txt":        "",
	})
	if _, err := New(src).CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "snap.pkg")
	if _, err := New(src).ExportSnapshot("snap", "", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	target, err := New(src).loadSnapshotRecord("snap")
	if err != nil {
		t.Fatal(err)
	}
	pkg := &Package{
		Format:   packageFormat,
		Version:  packageVersion,
		Snapshot: target,
		Objects:  []PackageObject{},
	}
	for _, digest := range sortedDigests(target.Entries) {
		content, err := os.ReadFile(filepath.Join(src, "objects", digest))
		if err != nil {
			t.Fatal(err)
		}
		pkg.Objects = append(pkg.Objects, PackageObject{
			Digest: digest,
			Size:   int64(len(content)),
			Data:   stdBase64(content),
		})
	}
	want, err := marshalPackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("exported package differs from the old in-memory format\nwant:\n%s\ngot:\n%s", want, got)
	}
}

// TestIncrementalExportedFileIsByteIdenticalToOldFormat covers the delta shape
// (present base, omitted objects) end to end.
func TestIncrementalExportedFileIsByteIdenticalToOldFormat(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"keep.txt": "same", "change.txt": "old"})
	if _, err := New(src).CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).Put("change.txt", writeFile(t, "new")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).Put("new.txt", writeFile(t, "brand new")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).CreateSnapshot("target"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "target.pkg")
	if _, err := New(src).ExportSnapshot("target", "base", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	store := New(src)
	target, err := store.loadSnapshotRecord("target")
	if err != nil {
		t.Fatal(err)
	}
	baseSnap, err := store.loadSnapshotRecord("base")
	if err != nil {
		t.Fatal(err)
	}
	carry := digestsReferenced(target.Entries)
	for d := range digestsReferenced(baseSnap.Entries) {
		delete(carry, d)
	}
	pkg := &Package{
		Format:   packageFormat,
		Version:  packageVersion,
		Snapshot: target,
		Base:     &baseSnap,
		Objects:  []PackageObject{},
	}
	for _, digest := range sortedStringSet(carry) {
		content, err := os.ReadFile(filepath.Join(src, "objects", digest))
		if err != nil {
			t.Fatal(err)
		}
		pkg.Objects = append(pkg.Objects, PackageObject{
			Digest: digest,
			Size:   int64(len(content)),
			Data:   stdBase64(content),
		})
	}
	want, err := marshalPackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("incremental package differs from the old in-memory format\nwant:\n%s\ngot:\n%s", want, got)
	}
}

// TestExportMemoryIsIndependentOfObjectSize is the constant-memory regression
// guard: exporting one large object must not retain its bytes (raw, base64, or
// marshalled JSON). It measures retained Go heap across an export of a sparse
// 48 MiB object; the old in-memory implementation held on the order of 150 MiB
// across that export, while the streaming path holds only fixed-size buffers.
func TestExportMemoryIsIndependentOfObjectSize(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-object memory test in short mode")
	}
	const size = 48 << 20 // 48 MiB of (sparse) zero bytes

	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	// Stage a sparse zero file as the artifact's source; Put itself streams.
	src := filepath.Join(t.TempDir(), "big.bin")
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	entry, err := store.Put("big.bin", src)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Digest != digestOfN(size) {
		t.Fatalf("digest mismatch")
	}
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "big.pkg")

	var ms1, ms2 runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms1)
	if res, err := store.ExportSnapshot("snap", "", out); err != nil {
		t.Fatalf("export: %v", err)
	} else if res.Entries != 1 || res.Objects != 1 {
		t.Fatalf("result=%+v", res)
	}
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms2)

	// TotalAlloc is cumulative and never falls, so it captures the bytes an
	// implementation churned through even after they are freed — unlike
	// HeapAlloc, which a post-hoc GC would reclaim for either implementation.
	// The old in-memory path allocated roughly the raw object, its base64
	// expansion, and the marshalled JSON (≈3.7x the object size) per export;
	// the streaming path allocates only fixed buffers regardless of size.
	allocated := ms2.TotalAlloc - ms1.TotalAlloc
	const tolerance = 16 << 20
	if allocated > tolerance {
		t.Fatalf("export allocated %d bytes handling a %d-byte object; expected a fixed, size-independent amount", allocated, size)
	}

	// The package must still import and restore the object exactly.
	dst := filepath.Join(t.TempDir(), "vault-dst")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(out); err != nil {
		t.Fatalf("import: %v", err)
	}
	if err := New(dst).RestoreSnapshot("snap"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	entries, err := New(dst).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "big.bin" || entries[0].Digest != entry.Digest || entries[0].Size != size {
		t.Fatalf("restored entries=%+v", entries)
	}
	// Verify the restored large object by hash rather than materializing it.
	obj, err := os.Open(filepath.Join(dst, "objects", entry.Digest))
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Close()
	h := sha256.New()
	n, err := io.CopyBuffer(h, obj, make([]byte, 32*1024))
	if err != nil {
		t.Fatal(err)
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != entry.Digest {
		t.Fatalf("restored large object mismatch: n=%d", n)
	}
}
