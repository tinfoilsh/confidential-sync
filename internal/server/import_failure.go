package server

import (
	"context"
	"encoding/json"
	"errors"
)

// ImportFailureReason is the user-safe classification of why an import
// job ended without completing. It is surfaced in the status response
// and forwarded to the controlplane so the failure email can explain
// what went wrong without leaking internal error text.
type ImportFailureReason string

const (
	// ImportFailureTimeout means the job exceeded ImportJobBudget.
	ImportFailureTimeout ImportFailureReason = "timeout"
	// ImportFailureInvalidArchive means the upload could not be read as
	// a supported export (hash mismatch, unsafe ZIP, missing files, or
	// unparseable conversations).
	ImportFailureInvalidArchive ImportFailureReason = "invalid_archive"
	// ImportFailureLimitExceeded means the archive exceeded a v1 import
	// cap (conversations, messages, attachments, or entry sizes).
	ImportFailureLimitExceeded ImportFailureReason = "limit_exceeded"
	// ImportFailureKeyMismatch means the supplied CEK is not the user's
	// registered current key, so nothing was written.
	ImportFailureKeyMismatch ImportFailureReason = "key_mismatch"
	// ImportFailureInternal covers everything else (storage, network,
	// panics); the user is asked to retry.
	ImportFailureInternal ImportFailureReason = "internal"
)

// importFailureErr tags an error with the reason a job failed. Code that
// knows why it is failing wraps its error so the coordinator does not
// have to string-match.
type importFailureErr struct {
	reason ImportFailureReason
	err    error
}

func (e *importFailureErr) Error() string { return e.err.Error() }
func (e *importFailureErr) Unwrap() error { return e.err }

func importFailure(reason ImportFailureReason, err error) error {
	if err == nil {
		return nil
	}
	return &importFailureErr{reason: reason, err: err}
}

func invalidArchiveErr(msg string) error {
	return importFailure(ImportFailureInvalidArchive, errors.New(msg))
}

func limitExceededErr(msg string) error {
	return importFailure(ImportFailureLimitExceeded, errors.New(msg))
}

// classifyParseFailure tags a ParseEach error. The parsers fail with a
// JSON decode error when the archive is not a valid export; any other
// error originated in the emit callback and is already classified (or
// is a transport error the coordinator maps to internal/timeout).
func classifyParseFailure(err error) error {
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
		return importFailure(ImportFailureInvalidArchive, err)
	}
	return err
}

// classifyImportFailure maps a job error to its user-safe reason.
// Tagged errors win; a budget expiry is reported as a timeout so the
// user learns their archive was too large to finish rather than seeing
// a generic failure.
func classifyImportFailure(ctx context.Context, err error) ImportFailureReason {
	var tagged *importFailureErr
	if errors.As(err, &tagged) {
		return tagged.reason
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ImportFailureTimeout
	}
	var appErr *AppError
	if errors.As(err, &appErr) && (appErr.Code == CodeStaleKey || appErr.Code == CodeUnknownKey) {
		return ImportFailureKeyMismatch
	}
	return ImportFailureInternal
}

// importFailureMessage is the status-response text for a reason. The
// email template on the controlplane carries the longer explanation.
func importFailureMessage(reason ImportFailureReason) string {
	switch reason {
	case ImportFailureTimeout:
		return "import timed out"
	case ImportFailureInvalidArchive:
		return "import archive could not be read"
	case ImportFailureLimitExceeded:
		return "import archive exceeds size limits"
	case ImportFailureKeyMismatch:
		return "import key is not the current key"
	default:
		return "import failed"
	}
}
