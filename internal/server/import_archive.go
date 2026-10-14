package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
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
		// A staging fetch failure is ours, not the user's, even when it
		// surfaces as a truncated read while the ZIP reader is decoding.
		return nil, importFailure(ImportFailureInternal, fmt.Errorf("import: fetch staged chunk: %w", err))
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
	zr                 *zip.Reader
	index              *importer.Index
	files              map[string]*zip.File
	conversationsFiles []string
	plainJSON          []byte
}

// zipLocalHeader is the signature every ZIP file starts with. A staged
// upload that has it but no readable central directory is a ZIP that
// was cut short, not a JSON export.
var zipLocalHeader = []byte("PK\x03\x04")

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
			if job.Source == string(importer.SourceTinfoilBackup) {
				return nil, invalidArchiveErr(ImportDetailNotZip, "import: tinfoil backup must be a ZIP archive")
			}
			truncated, terr := hasZipLocalHeader(reader)
			if terr != nil {
				return nil, terr
			}
			if truncated {
				return nil, invalidArchiveErr(ImportDetailCorruptZip, "import: archive is a truncated ZIP")
			}
			plain, perr := readAllStaged(reader, MaxImportJSONBytes)
			if perr != nil {
				return nil, perr
			}
			return &importArchive{plainJSON: plain}, nil
		}
		return nil, classifyArchiveReadErr(fmt.Errorf("import: open archive: %w", err))
	}

	arch := &importArchive{zr: zr, files: make(map[string]*zip.File)}
	if err := arch.validateAndIndex(job.Source); err != nil {
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
		return invalidArchiveErr(ImportDetailHashMismatch, "import: archive hash mismatch")
	}
	return nil
}

func hasZipLocalHeader(r *stagedArchiveReader) (bool, error) {
	if r.totalBytes < int64(len(zipLocalHeader)) {
		return false, nil
	}
	head := make([]byte, len(zipLocalHeader))
	if _, err := r.ReadAt(head, 0); err != nil {
		return false, fmt.Errorf("import: read archive header: %w", err)
	}
	return bytes.Equal(head, zipLocalHeader), nil
}

func readAllStaged(r *stagedArchiveReader, maxBytes int64) ([]byte, error) {
	sr := io.NewSectionReader(r, 0, r.totalBytes)
	limited := io.LimitReader(sr, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("import: read archive: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, limitExceededErr(ImportDetailTooLarge, "import: conversations file exceeds size limit")
	}
	return data, nil
}

func (a *importArchive) validateAndIndex(source string) error {
	if len(a.zr.File) > MaxImportEntries {
		return limitExceededErr(ImportDetailTooManyEntries, "import: archive has too many entries")
	}
	var totalUncompressed uint64
	names := make([]string, 0, len(a.zr.File))
	var conversationsCandidates []string
	for _, f := range a.zr.File {
		info := f.FileInfo()
		if info.IsDir() {
			if source == string(importer.SourceTinfoilBackup) {
				return invalidArchiveErr(ImportDetailUnsafeEntry, "import: native backup contains an unlisted directory entry")
			}
			continue
		}
		mode := f.Mode()
		if mode&os.ModeSymlink != 0 || !mode.IsRegular() {
			return invalidArchiveErr(ImportDetailUnsafeEntry, "import: archive contains an unsafe entry")
		}
		name, ok := safeZipName(f.Name)
		if !ok {
			return invalidArchiveErr(ImportDetailUnsafeEntry, "import: archive contains an unsafe path")
		}
		if _, dup := a.files[name]; dup {
			return invalidArchiveErr(ImportDetailUnsafeEntry, "import: archive contains a duplicate path")
		}
		if f.UncompressedSize64 > uint64(MaxImportJSONBytes) {
			return limitExceededErr(ImportDetailTooLarge, "import: archive entry exceeds size limit")
		}
		totalUncompressed += f.UncompressedSize64
		if totalUncompressed > uint64(MaxImportUncompressedBytes) {
			return limitExceededErr(ImportDetailTooLarge, "import: archive uncompressed size exceeds limit")
		}
		a.files[name] = f
		names = append(names, name)
		if isConversationsFile(name) {
			conversationsCandidates = append(conversationsCandidates, name)
		}
	}
	a.index = importer.NewIndex(names)
	if source == string(importer.SourceTinfoilBackup) {
		if _, ok := a.files[nativeManifestPath]; !ok {
			return invalidArchiveErr(ImportDetailMissingManifest, "import: archive is missing manifest.json")
		}
		return nil
	}
	a.conversationsFiles = selectConversationsFiles(conversationsCandidates)
	if len(a.conversationsFiles) == 0 {
		return invalidArchiveErr(ImportDetailMissingConversations, "import: archive is missing conversations.json")
	}
	return nil
}

func (a *importArchive) readEntry(name string, maxBytes int64) ([]byte, error) {
	f, ok := a.files[name]
	if !ok {
		return nil, errors.New("import: archive entry not found")
	}
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("import: open archive entry: %w", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("import: read archive entry: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, limitExceededErr(ImportDetailTooLarge, "import: archive entry exceeds size limit")
	}
	return data, nil
}

// splitConversationsFile matches the parts of a split export. ChatGPT
// writes conversations-000.json, conversations-001.json, ... instead of
// one conversations.json once an account's history is large.
var splitConversationsFile = regexp.MustCompile(`^conversations-([0-9]+)\.json$`)

func isConversationsFile(name string) bool {
	base := path.Base(name)
	return base == "conversations.json" || splitConversationsFile.MatchString(base)
}

// selectConversationsFiles returns every conversations file in the
// shallowest directory that has one, so a root-level export wins over a
// nested copy. Split parts are read in numeric order.
func selectConversationsFiles(candidates []string) []string {
	if len(candidates) == 0 {
		return nil
	}
	shallowest := candidates[0]
	for _, name := range candidates[1:] {
		if strings.Count(name, "/") < strings.Count(shallowest, "/") {
			shallowest = name
		}
	}
	dir := path.Dir(shallowest)
	var selected []string
	for _, name := range candidates {
		if path.Dir(name) == dir {
			selected = append(selected, name)
		}
	}
	sort.SliceStable(selected, func(i, j int) bool {
		return conversationsFileOrder(selected[i]) < conversationsFileOrder(selected[j])
	})
	return selected
}

// conversationsFileOrder sorts conversations.json first, then split
// parts by their number.
func conversationsFileOrder(name string) int64 {
	m := splitConversationsFile.FindStringSubmatch(path.Base(name))
	if m == nil {
		return -1
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return math.MaxInt64
	}
	return n
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

// eachConversationsFile hands fn one conversations document at a time,
// so a split export never holds more than one part in memory.
func (a *importArchive) eachConversationsFile(fn func([]byte) error) error {
	if a.zr == nil {
		return fn(a.plainJSON)
	}
	for _, name := range a.conversationsFiles {
		data, err := a.readConversationsFile(name)
		if err != nil {
			return err
		}
		if err := fn(data); err != nil {
			return err
		}
	}
	return nil
}

func (a *importArchive) readConversationsFile(name string) ([]byte, error) {
	f, ok := a.files[name]
	if !ok {
		return nil, invalidArchiveErr(ImportDetailMissingConversations, "import: conversations file not found")
	}
	rc, err := f.Open()
	if err != nil {
		return nil, classifyArchiveReadErr(fmt.Errorf("import: open conversations file: %w", err))
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, int64(MaxImportJSONBytes)+1))
	if err != nil {
		return nil, classifyArchiveReadErr(fmt.Errorf("import: read conversations file: %w", err))
	}
	if int64(len(data)) > int64(MaxImportJSONBytes) {
		return nil, limitExceededErr(ImportDetailTooLarge, "import: conversations file exceeds size limit")
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
