package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Entry struct {
	Name      string    `json:"name"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
}

type index struct {
	Entries map[string]Entry `json:"entries"`
}

type Store struct{ root string }

func New(root string) *Store { return &Store{root: root} }

func (s *Store) Init() error {
	if strings.TrimSpace(s.root) == "" {
		return errors.New("root is required")
	}
	if err := os.MkdirAll(filepath.Join(s.root, "objects"), 0o755); err != nil {
		return err
	}
	_, err := os.Stat(s.indexPath())
	if errors.Is(err, os.ErrNotExist) {
		return s.save(index{Entries: map[string]Entry{}})
	}
	return err
}

func (s *Store) Put(name, source string) (Entry, error) {
	if err := validateName(name); err != nil {
		return Entry{}, err
	}
	if source == "" {
		return Entry{}, errors.New("file is required")
	}
	if err := s.Init(); err != nil {
		return Entry{}, err
	}
	in, err := os.Open(source)
	if err != nil {
		return Entry{}, err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Join(s.root, "objects"), ".upload-*")
	if err != nil {
		return Entry{}, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(tmp, hash), in)
	closeErr := tmp.Close()
	if copyErr != nil {
		return Entry{}, copyErr
	}
	if closeErr != nil {
		return Entry{}, closeErr
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	object := s.objectPath(digest)
	if _, err := os.Stat(object); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(tmpName, object); err != nil {
			return Entry{}, err
		}
	}
	idx, err := s.load()
	if err != nil {
		return Entry{}, err
	}
	entry := Entry{Name: name, Digest: digest, Size: size, CreatedAt: time.Now().UTC()}
	idx.Entries[name] = entry
	if err := s.save(idx); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

func (s *Store) Get(name, output string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if output == "" {
		return errors.New("output is required")
	}
	idx, err := s.load()
	if err != nil {
		return err
	}
	entry, ok := idx.Entries[name]
	if !ok {
		return fmt.Errorf("artifact %q not found", name)
	}
	in, err := os.Open(s.objectPath(entry.Digest))
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(output)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func (s *Store) List() ([]Entry, error) {
	idx, err := s.load()
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(idx.Entries))
	for _, entry := range idx.Entries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func (s *Store) Verify() (int, error) {
	entries, err := s.List()
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		file, err := os.Open(s.objectPath(entry.Digest))
		if err != nil {
			return 0, fmt.Errorf("verify %q: %w", entry.Name, err)
		}
		hash := sha256.New()
		size, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return 0, fmt.Errorf("verify %q: read failed", entry.Name)
		}
		if size != entry.Size || hex.EncodeToString(hash.Sum(nil)) != entry.Digest {
			return 0, fmt.Errorf("verify %q: content mismatch", entry.Name)
		}
	}
	return len(entries), nil
}

func (s *Store) load() (index, error) {
	data, err := os.ReadFile(s.indexPath())
	if err != nil {
		return index{}, err
	}
	var idx index
	if err := json.Unmarshal(data, &idx); err != nil {
		return index{}, err
	}
	if idx.Entries == nil {
		idx.Entries = map[string]Entry{}
	}
	return idx, nil
}

func (s *Store) save(idx index) error {
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(s.root, ".index-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.indexPath())
}

func (s *Store) indexPath() string               { return filepath.Join(s.root, "index.json") }
func (s *Store) objectPath(digest string) string { return filepath.Join(s.root, "objects", digest) }

func validateName(name string) error {
	if strings.TrimSpace(name) == "" || filepath.IsAbs(name) || name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "\\") {
		return errors.New("name must be a nonempty relative slash-separated path")
	}
	clean := filepath.Clean(name)
	if clean != name || strings.HasPrefix(clean, "../") {
		return errors.New("name must be normalized and remain within the vault namespace")
	}
	return nil
}
