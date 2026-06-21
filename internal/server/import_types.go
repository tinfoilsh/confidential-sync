package server

// Wire shapes for the off-device chat import endpoints. The webapp
// uploads a raw ChatGPT/Claude/Tinfoil export archive in chunks, hands
// the enclave its CEK, and the enclave parses, seals, and stores every
// chat + attachment off-device, emailing the user on completion.

type ImportCreateRequest struct {
	Source        string `json:"source"`
	TotalBytes    int64  `json:"total_bytes"`
	TotalChunks   int    `json:"total_chunks"`
	ArchiveSHA256 string `json:"archive_sha256"`
}

type ImportCreateResponse struct {
	JobID    string `json:"job_id"`
	UploadID string `json:"upload_id"`
}

type ImportUploadRequest struct {
	UploadID    string `json:"upload_id"`
	ChunkIndex  int    `json:"chunk_index"`
	ChunkSHA256 string `json:"chunk_sha256"`
	Data        string `json:"data"` // base64 raw chunk bytes
}

type ImportStartRequest struct {
	JobID string `json:"job_id"`
	Key   string `json:"key"` // base64 raw 32-byte CEK
}

type ImportStatusRequest struct {
	JobID string `json:"job_id"`
}

type ImportStatusResponse struct {
	Status   string   `json:"status"`
	Imported int      `json:"imported"`
	Failed   int      `json:"failed"`
	Total    int      `json:"total"`
	Errors   []string `json:"errors,omitempty"`
	JobID    string   `json:"job_id,omitempty"`
}

// Import safety limits. These are v1 caps; raising them is a deliberate
// decision that needs memory/runtime review and test updates.
const (
	// MaxImportArchiveBytes is the largest compressed archive upload.
	MaxImportArchiveBytes = 512 << 20 // 512 MiB
	// MaxImportChunkBytes is the fixed raw chunk size the client uploads
	// with (the last chunk may be smaller). Mirrored in the webapp.
	MaxImportChunkBytes = 8 << 20 // 8 MiB
	// MaxImportUncompressedBytes caps total decompressed ZIP entry bytes.
	MaxImportUncompressedBytes = 2 << 30 // 2 GiB
	// MaxImportEntries caps the number of ZIP entries.
	MaxImportEntries = 50_000
	// MaxImportConversations caps parsed conversations.
	MaxImportConversations = 100_000
	// MaxImportMessages caps parsed messages across the archive.
	MaxImportMessages = 2_000_000
	// MaxImportAttachments caps extracted attachments across the archive.
	MaxImportAttachments = 100_000
	// MaxImportAttachmentBytes caps a single decoded binary attachment.
	MaxImportAttachmentBytes = 32 << 20 // 32 MiB
	// MaxImportJSONBytes caps the decompressed conversations.json.
	MaxImportJSONBytes = 256 << 20 // 256 MiB
	// MaxImportJobErrors caps how many per-item warnings a job retains.
	MaxImportJobErrors = 100
)
