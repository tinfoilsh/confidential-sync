package server

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/importer"
)

func TestImportFailureKeepsInnermostTag(t *testing.T) {
	inner := limitExceededErr("import: native backup count limit exceeded")
	wrapped := importFailure(ImportFailureInvalidArchive, fmt.Errorf("import: validate: %w", inner))
	if got := classifyImportFailure(context.Background(), wrapped); got != ImportFailureLimitExceeded {
		t.Fatalf("outer wrap masked the limit tag: got %q", got)
	}
}

func TestClassifyImportFailure(t *testing.T) {
	expired, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-expired.Done()

	cases := []struct {
		name string
		ctx  context.Context
		err  error
		want ImportFailureReason
	}{
		{"parser rejects export", context.Background(), classifyParseFailure(fmt.Errorf("%w: bad json", importer.ErrInvalidExport)), ImportFailureInvalidArchive},
		{"emit callback transport error is not an archive problem", context.Background(), classifyParseFailure(errors.New("push: connection reset")), ImportFailureInternal},
		{"zip corruption", context.Background(), classifyArchiveReadErr(fmt.Errorf("import: open archive: %w", zip.ErrFormat)), ImportFailureInvalidArchive},
		{"chunk fetch timeout while reading zip", expired, classifyArchiveReadErr(fmt.Errorf("import: read conversations.json: %w", context.DeadlineExceeded)), ImportFailureTimeout},
		{"chunk fetch failure while reading zip", context.Background(), classifyArchiveReadErr(importFailure(ImportFailureInternal, errors.New("import: fetch staged chunk: 503"))), ImportFailureInternal},
		{"truncated chunk fetch is not archive corruption", context.Background(), classifyArchiveReadErr(importFailure(ImportFailureInternal, fmt.Errorf("import: fetch staged chunk: %w", io.ErrUnexpectedEOF))), ImportFailureInternal},
		{"chunk fetch deadline wins over its internal tag", expired, importFailure(ImportFailureInternal, fmt.Errorf("import: fetch staged chunk: %w", context.DeadlineExceeded)), ImportFailureTimeout},
		{"stale key", context.Background(), &AppError{Code: CodeStaleKey}, ImportFailureKeyMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyImportFailure(tc.ctx, tc.err); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
