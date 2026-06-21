package importer

import (
	"path"
	"strings"
)

// Index is a lookup over the safe, normalized entry names of an
// archive. Parsers resolve attachment references only through this
// index so a malicious archive cannot point an attachment at an
// arbitrary path. The caller builds it from the ZIP central directory
// after rejecting unsafe entries (traversal, absolute paths, symlinks).
type Index struct {
	names  []string
	byName map[string]struct{}
	byBase map[string]string
}

// NewIndex builds an index from already-validated safe entry names.
// The first entry to claim a basename wins, which is deterministic for
// a given archive ordering.
func NewIndex(names []string) *Index {
	idx := &Index{
		names:  make([]string, 0, len(names)),
		byName: make(map[string]struct{}, len(names)),
		byBase: make(map[string]string, len(names)),
	}
	for _, n := range names {
		clean := normalizeEntry(n)
		if clean == "" {
			continue
		}
		if _, ok := idx.byName[clean]; ok {
			continue
		}
		idx.byName[clean] = struct{}{}
		idx.names = append(idx.names, clean)
		base := path.Base(clean)
		if _, ok := idx.byBase[base]; !ok {
			idx.byBase[base] = clean
		}
	}
	return idx
}

func normalizeEntry(name string) string {
	clean := path.Clean("/" + strings.ReplaceAll(name, "\\", "/"))
	return strings.TrimPrefix(clean, "/")
}

// Exact resolves a reference that should match an entry path exactly
// (after normalization), e.g. a Tinfoil exportPath.
func (i *Index) Exact(ref string) (string, bool) {
	clean := normalizeEntry(ref)
	if clean == "" {
		return "", false
	}
	if _, ok := i.byName[clean]; ok {
		return clean, true
	}
	if name, ok := i.byBase[path.Base(clean)]; ok {
		return name, true
	}
	return "", false
}

// ByIDPrefix resolves an attachment file id (e.g. ChatGPT "file-abc123")
// to the first entry whose basename starts with that id. ChatGPT and
// Claude name media files using the source file id as a prefix.
func (i *Index) ByIDPrefix(id string) (string, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", false
	}
	if name, ok := i.byBase[id]; ok {
		return name, true
	}
	for _, n := range i.names {
		if strings.HasPrefix(path.Base(n), id) {
			return n, true
		}
	}
	return "", false
}

// Len reports how many safe entries the index holds.
func (i *Index) Len() int { return len(i.names) }
