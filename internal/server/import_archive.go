package server

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/importer"
)

// maxCachedChunks bounds the decrypted-chunk LRU the archive reader
// keeps while the zip layer reads the central directory. 8 chunks at
// MaxImportChunkBytes is 64 MiB worst-case.
const maxCachedChunks = 8

// stagedArchiveReader is a bounded io.ReaderAt over the encrypted
// archive chunks staged in buckets. The zip stdlib reads the central
// directory through this without the full archive ever being held in
// memory; only a small LRU of decrypted chunks is retained.
type stagedArchiveReader struct {
	ctx         context.Context
	deps        Deps
	owner       string
	uploadID    string
	stagingKey  []byte
	chunkSize   int64
	totalBytes  int64
	totalChunks int

	mu    sync.Mutex
	cache map[int][]byte
	order []int
}

func (r *stagedArchiveReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("import: negative read offset")
	}
	if off >= r.totalBytes {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) {
		cur := off + int64(n)
		if cur >= r.totalBytes {
			return n, io.EOF
		}
		idx := int(cur / r.chunkSize)
		chunk, err := r.getChunk(idx)
		if err != nil {
			return n, err
		}
		within := int(cur - int64(idx)*r.chunkSize)
		copied := copy(p[n:], chunk[within:])
		n += copied
	}
	return n, nil
}

func (r *stagedArchiveReader) expectedChunkLen(idx int) int64 {
	start := int64(idx) * r.chunkSize
	remaining := r.totalBytes - start
	if remaining < r.chunkSize {
		return remaining
	}
	return r.chunkSize
}

func (r *stagedArchiveReader) getChunk(idx int) ([]byte, error) {
	r.mu.Lock()
	if chunk, ok := r.cache[idx]; ok {
		r.touchLocked(idx)
		r.mu.Unlock()
		return chunk, nil
	}
	r.mu.Unlock()

	chunk, err := r.deps.Buckets.Get(r.ctx, r.owner, importChunkToken(r.uploadID, idx), r.stagingKey)
	if err != nil {
		return nil, fmt.Errorf("import: fetch staged chunk: %w", err)
	}
	if int64(len(chunk)) != r.expectedChunkLen(idx) {
		return nil, fmt.Errorf("import: staged chunk %d has unexpected size", idx)
	}

	r.mu.Lock()
	r.cache[idx] = chunk
	r.order = append(r.order, idx)
	for len(r.order) > maxCachedChunks {
		evict := r.order[0]
		r.order = r.order[1:]
		delete(r.cache, evict)
	}
	r.mu.Unlock()
	return chunk, nil
}

func (r *stagedArchiveReader) touchLocked(idx int) {
	for i, seen := range r.order {
		if seen == idx {
			copy(r.order[i:], r.order[i+1:])
			r.order[len(r.order)-1] = idx
			return
		}
	}
}

// importChunkToken is the buckets object key for one staged chunk. The
// per-user tenant prefix is applied by the buckets client, so this key
// only needs to be unique within the user's namespace.
func importChunkToken(uploadID string, idx int) string {
	return fmt.Sprintf("import-staging-%s-chunk-%d", uploadID, idx)
}

// importArchive is the validated, safe view of a staged archive. It is
// either a ZIP (with a safe entry index) or a bare conversations.json
// when the upload was a plain JSON export with no attachments.
type importArchive struct {
	zr                *zip.Reader
	index             *importer.Index
	files             map[string]*zip.File
	conversationsName string
	plainJSON         []byte
}

// openStagedArchive verifies the archive hash, then opens it as a ZIP
// (enforcing the safety limits) or treats it as plain conversations.json
// when the bytes are not a ZIP container.
func openStagedArchive(ctx context.Context, deps Deps, owner string, job *ImportJobState) (*importArchive, error) {
	reader := &stagedArchiveReader{
		ctx:         ctx,
		deps:        deps,
		owner:       owner,
		uploadID:    job.UploadID,
		stagingKey:  job.stagingKey,
		chunkSize:   MaxImportChunkBytes,
		totalBytes:  job.TotalBytes,
		totalChunks: job.TotalChunks,
		cache:       make(map[int][]byte),
	}

	if err := verifyStagedArchiveHash(reader, job.ArchiveSHA256); err != nil {
		return nil, err
	}

	zr, err := zip.NewReader(reader, job.TotalBytes)
	if err != nil {
		if errors.Is(err, zip.ErrFormat) {
			plain, perr := readAllStaged(reader, MaxImportJSONBytes)
			if perr != nil {
				return nil, perr
			}
			return &importArchive{plainJSON: plain}, nil
		}
		return nil, fmt.Errorf("import: open archive: %w", err)
	}

	arch := &importArchive{zr: zr, files: make(map[string]*zip.File)}
	if err := arch.validateAndIndex(); err != nil {
		return nil, err
	}
	return arch, nil
}

// verifyStagedArchiveHash streams every chunk once and checks the full
// archive SHA-256 before any parsing happens.
func verifyStagedArchiveHash(r *stagedArchiveReader, wantHex string) error {
	h := sha256.New()
	for i := 0; i < r.totalChunks; i++ {
		chunk, err := r.getChunk(i)
		if err != nil {
			return err
		}
		h.Write(chunk)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, wantHex) {
		return errors.New("import: archive hash mismatch")
	}
	return nil
}

func readAllStaged(r *stagedArchiveReader, maxBytes int64) ([]byte, error) {
	sr := io.NewSectionReader(r, 0, r.totalBytes)
	limited := io.LimitReader(sr, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("import: read archive: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("import: conversations.json exceeds size limit")
	}
	return data, nil
}

func (a *importArchive) validateAndIndex() error {
	if len(a.zr.File) > MaxImportEntries {
		return fmt.Errorf("import: archive has too many entries")
	}
	var totalUncompressed uint64
	names := make([]string, 0, len(a.zr.File))
	for _, f := range a.zr.File {
		info := f.FileInfo()
		if info.IsDir() {
			continue
		}
		mode := f.Mode()
		if mode&os.ModeSymlink != 0 || !mode.IsRegular() {
			return errors.New("import: archive contains an unsafe entry")
		}
		name, ok := safeZipName(f.Name)
		if !ok {
			return errors.New("import: archive contains an unsafe path")
		}
		if _, dup := a.files[name]; dup {
			return errors.New("import: archive contains a duplicate path")
		}
		if f.UncompressedSize64 > uint64(MaxImportJSONBytes) {
			return errors.New("import: archive entry exceeds size limit")
		}
		totalUncompressed += f.UncompressedSize64
		if totalUncompressed > uint64(MaxImportUncompressedBytes) {
			return errors.New("import: archive uncompressed size exceeds limit")
		}
		a.files[name] = f
		names = append(names, name)
		if a.conversationsName == "" || preferConversations(name, a.conversationsName) {
			if path.Base(name) == "conversations.json" {
				a.conversationsName = name
			}
		}
	}
	a.index = importer.NewIndex(names)
	if a.conversationsName == "" {
		return errors.New("import: archive is missing conversations.json")
	}
	return nil
}

// preferConversations prefers the shallowest conversations.json so a
// root-level file wins over a nested one.
func preferConversations(candidate, current string) bool {
	return strings.Count(candidate, "/") < strings.Count(current, "/")
}

// safeZipName normalizes a ZIP entry name and rejects absolute paths
// and parent-directory traversal. The returned name is the normalized
// form used as the index/file-map key.
func safeZipName(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	if strings.ContainsRune(name, 0) {
		return "", false
	}
	cleaned := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(cleaned, "/") {
		return "", false
	}
	norm := path.Clean(cleaned)
	if norm == "." || norm == ".." || strings.HasPrefix(norm, "../") {
		return "", false
	}
	return norm, true
}

func (a *importArchive) readConversations() ([]byte, error) {
	if a.zr == nil {
		return a.plainJSON, nil
	}
	f, ok := a.files[a.conversationsName]
	if !ok {
		return nil, errors.New("import: conversations.json not found")
	}
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("import: open conversations.json: %w", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, int64(MaxImportJSONBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("import: read conversations.json: %w", err)
	}
	if int64(len(data)) > int64(MaxImportJSONBytes) {
		return nil, errors.New("import: conversations.json exceeds size limit")
	}
	return data, nil
}

// openBinary reads one attachment entry by its normalized name with a
// hard decompressed-size cap. It returns ErrNotFound semantics via a
// nil/empty result the caller treats as a recoverable warning.
func (a *importArchive) openBinary(name string) ([]byte, error) {
	if a.zr == nil {
		return nil, errors.New("import: no binary entries in plain json archive")
	}
	f, ok := a.files[name]
	if !ok {
		return nil, fmt.Errorf("import: binary entry not found")
	}
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("import: open binary entry: %w", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, int64(MaxImportAttachmentBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("import: read binary entry: %w", err)
	}
	if int64(len(data)) > int64(MaxImportAttachmentBytes) {
		return nil, errors.New("import: binary entry exceeds size limit")
	}
	return data, nil
}

func (a *importArchive) entryIndex() *importer.Index {
	if a.index != nil {
		return a.index
	}
	return importer.NewIndex(nil)
}
