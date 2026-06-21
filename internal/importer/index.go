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
	return "", false
}

// Basename resolves a reference by basename only. Formats whose exports
// provide bare filenames instead of archive-relative paths opt into this
// weaker match explicitly.
func (i *Index) Basename(ref string) (string, bool) {
	clean := normalizeEntry(ref)
	if clean == "" {
		return "", false
	}
	name, ok := i.byBase[path.Base(clean)]
	return name, ok
}

// ByIDPrefix resolves an attachment file id (e.g. ChatGPT "file-abc123")
// to a unique entry whose basename contains that id as an exact stem or
// prefix. ChatGPT and Claude name media files using the source file id
// as a prefix.
func (i *Index) ByIDPrefix(id string) (string, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", false
	}
	if name, ok := i.byBase[id]; ok {
		return name, true
	}
	if name, ok := i.uniqueIDStem(id); ok {
		return name, true
	}
	return i.uniqueIDPrefix(id)
}

func (i *Index) uniqueIDStem(id string) (string, bool) {
	var match string
	for _, n := range i.names {
		base := path.Base(n)
		if strings.TrimSuffix(base, path.Ext(base)) != id {
			continue
		}
		if match != "" {
			return "", false
		}
		match = n
	}
	return match, match != ""
}

func (i *Index) uniqueIDPrefix(id string) (string, bool) {
	var match string
	for _, n := range i.names {
		base := path.Base(n)
		if !strings.HasPrefix(base, id) || len(base) == len(id) {
			continue
		}
		switch base[len(id)] {
		case '.', '-', '_':
		default:
			continue
		}
		if match != "" {
			return "", false
		}
		match = n
	}
	return match, match != ""
}

// Len reports how many safe entries the index holds.
func (i *Index) Len() int { return len(i.names) }
