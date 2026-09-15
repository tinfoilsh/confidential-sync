package server

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
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
		{"request deadline without job expiry", context.Background(), fmt.Errorf("lookup: %w", context.DeadlineExceeded), ImportFailureRequestTimeout},
		{"network deadline without job expiry", context.Background(), &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, ImportFailureRequestTimeout},
		{"job expiry wins over lookup fallback", expired, importFailure(ImportFailureExistingChatCheck, errors.New("lookup failed")), ImportFailureTimeout},
		{"request deadline survives lookup wrapper", context.Background(), importFailure(ImportFailureExistingChatCheck, context.DeadlineExceeded), ImportFailureRequestTimeout},
		{"connection failure survives lookup wrapper", context.Background(), importFailure(ImportFailureExistingChatCheck, &net.OpError{Op: "dial", Err: errors.New("connection failed")}), ImportFailureServiceUnavailable},
		{"service error survives internal wrapper", context.Background(), importFailure(ImportFailureInternal, &controlplane.Error{StatusCode: http.StatusServiceUnavailable}), ImportFailureServiceUnavailable},
		{"rate limited", context.Background(), &controlplane.Error{StatusCode: http.StatusTooManyRequests}, ImportFailureRateLimited},
		{"gateway timeout", context.Background(), &controlplane.Error{StatusCode: http.StatusGatewayTimeout}, ImportFailureRequestTimeout},
		{"HTTP request timeout", context.Background(), &controlplane.Error{StatusCode: http.StatusRequestTimeout}, ImportFailureRequestTimeout},
		{"unauthorized", context.Background(), &controlplane.Error{StatusCode: http.StatusUnauthorized}, ImportFailureAuthorization},
		{"forbidden", context.Background(), &controlplane.Error{StatusCode: http.StatusForbidden}, ImportFailureAuthorization},
		{"unreadable prior import", context.Background(), importFailure(ImportFailureExistingChatCheck, &AppError{Code: CodeBadRequest}), ImportFailureExistingChatCheck},
		{"unknown prior key", context.Background(), importFailure(ImportFailureExistingChatCheck, &AppError{Code: CodeUnknownKey}), ImportFailureKeyMismatch},
		{"unknown tag is not exposed", context.Background(), importFailure("private-title", errors.New("private-message")), ImportFailureInternal},
		{"message text does not classify a timeout", context.Background(), errors.New("context deadline exceeded"), ImportFailureInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyImportFailure(tc.ctx, tc.err); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
