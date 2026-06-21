// Package importer parses ChatGPT, Claude, and Tinfoil chat export
// archives into the webapp's StoredChat JSON shape so the sync enclave
// can seal and store them off-device. Parsing is pure: it reads
// conversations JSON plus an index of safe archive entry names and
// emits one chat at a time. Resolving binary attachment bytes,
// sealing, and uploading are the caller's responsibility.
package importer

import (
	"strconv"
	"time"
)

// Source identifies the export format an archive came from.
type Source string

const (
	SourceChatGPT Source = "chatgpt"
	SourceClaude  Source = "claude"
	SourceTinfoil Source = "tinfoil"
)

// jsTime marshals to the same ISO-8601 string the browser produces for
// a Date via JSON.stringify (UTC, millisecond precision, trailing Z),
// so sealed chat JSON is byte-compatible with what cloud-storage writes.
type jsTime struct{ time.Time }

func (t jsTime) MarshalJSON() ([]byte, error) {
	if t.Time.IsZero() {
		return []byte("null"), nil
	}
	return []byte(strconv.Quote(t.Time.UTC().Format("2006-01-02T15:04:05.000Z"))), nil
}

// AttachmentType enumerates the attachment kinds v1 import supports.
type AttachmentType string

const (
	AttachmentImage    AttachmentType = "image"
	AttachmentDocument AttachmentType = "document"
)

// Attachment mirrors the webapp Attachment type. Only the fields the
// importer can populate are present; transient parser-only state
// (BinaryRef) is excluded from the sealed JSON via the json:"-" tag.
type Attachment struct {
	ID          string         `json:"id"`
	Type        AttachmentType `json:"type"`
	FileName    string         `json:"fileName"`
	MimeType    string         `json:"mimeType,omitempty"`
	TextContent string         `json:"textContent,omitempty"`
	Description string         `json:"description,omitempty"`
	FileSize    int64          `json:"fileSize,omitempty"`
	// EncryptionKey is the per-attachment key minted by the enclave's
	// attachment-put flow for binary attachments. Empty for documents.
	EncryptionKey string `json:"encryptionKey,omitempty"`

	// BinaryRef points at the archive entry holding this attachment's
	// raw bytes. It is parser-internal: the job loop resolves it,
	// uploads the bytes, then sets ID/EncryptionKey. Never serialized.
	BinaryRef string `json:"-"`
}

// Message mirrors the webapp Message type for the fields the importer
// produces. Optional fields are omitted when empty so the sealed JSON
// matches what the browser writes for the same content.
type Message struct {
	Role             string       `json:"role"`
	Content          string       `json:"content"`
	Attachments      []Attachment `json:"attachments,omitempty"`
	Timestamp        jsTime       `json:"timestamp"`
	Thoughts         string       `json:"thoughts,omitempty"`
	ThinkingDuration int          `json:"thinkingDuration,omitempty"`
}

// Chat mirrors the webapp StoredChat shape the cloud seal expects.
type Chat struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Messages    []Message `json:"messages"`
	CreatedAt   jsTime    `json:"createdAt"`
	IsLocalOnly bool      `json:"isLocalOnly"`
	ProjectID   string    `json:"projectId,omitempty"`

	// StableKey is a source-stable identifier (conversation id/uuid)
	// used by the caller to derive deterministic, idempotent chat ids.
	// Never serialized into the sealed chat JSON.
	StableKey string `json:"-"`
}
