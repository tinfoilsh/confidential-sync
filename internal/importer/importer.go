package importer

import (
	"fmt"
	"strings"
	"time"
)

// Options configures a parse run.
type Options struct {
	// GenerateID returns the stable, deterministic chat id for a parsed
	// conversation. stableKey is a source-stable identifier (conversation
	// id/uuid, or a derived hash when the source has none); createdAt is
	// the conversation creation time. The caller supplies this so import
	// reruns produce identical ids and stay idempotent.
	GenerateID func(stableKey string, createdAt time.Time) string

	// Index resolves attachment references to safe archive entries. May
	// be nil for sources that carry only inline/text attachments.
	Index *Index
}

func (o Options) id(stableKey string, createdAt time.Time) string {
	if o.GenerateID != nil {
		return o.GenerateID(stableKey, createdAt)
	}
	return stableKey
}

// Result summarizes a parse run. Counts feed the job status and the
// completion email; Deferred records data v1 import intentionally skips
// (e.g. Claude projects) so it is reported rather than silently dropped.
type Result struct {
	Conversations int
	Messages      int
	Attachments   int
	Deferred      []string
}

// EmitFunc receives one parsed chat at a time. Returning an error stops
// the parse. The chat is owned by the callback once delivered.
type EmitFunc func(*Chat) error

// ParseEach streams conversations from the given root JSON document for
// the requested source, invoking emit once per chat. It never builds a
// slice of every chat, so large archives do not have to be held in
// memory all at once.
func ParseEach(source Source, conversationsJSON []byte, opts Options, emit EmitFunc) (Result, error) {
	if emit == nil {
		return Result{}, fmt.Errorf("importer: emit callback is required")
	}
	switch source {
	case SourceChatGPT:
		return parseChatGPT(conversationsJSON, opts, emit)
	case SourceClaude:
		return parseClaude(conversationsJSON, opts, emit)
	case SourceTinfoil:
		return parseTinfoil(conversationsJSON, opts, emit)
	default:
		return Result{}, fmt.Errorf("importer: unsupported source %q", source)
	}
}

// trimFileID strips ChatGPT's file-service URI scheme so a reference can
// be matched against archive entry basenames.
func trimFileID(ref string) string {
	ref = strings.TrimSpace(ref)
	ref = strings.TrimPrefix(ref, "file-service://")
	ref = strings.TrimPrefix(ref, "sediment://")
	return ref
}
