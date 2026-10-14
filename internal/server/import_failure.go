package server

import (
	"archive/zip"
	"compress/flate"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/importer"
)

// ImportFailureReason is the user-safe classification of why an import
// job ended without completing. It is surfaced in the status response
// and forwarded to the controlplane so the failure email can explain
// what went wrong without leaking internal error text.
type ImportFailureReason string

const (
	// ImportFailureTimeout means the job made no progress for
	// ImportStallTimeout and was canceled.
	ImportFailureTimeout ImportFailureReason = "timeout"
	// ImportFailureInvalidArchive means the upload could not be read as
	// a supported export (hash mismatch, unsafe ZIP, missing files, or
	// unparseable conversations).
	ImportFailureInvalidArchive ImportFailureReason = "invalid_archive"
	// ImportFailureLimitExceeded means the archive exceeded a v1 import
	// cap (conversations, messages, attachments, or entry sizes).
	ImportFailureLimitExceeded ImportFailureReason = "limit_exceeded"
	// ImportFailureKeyMismatch means the supplied key cannot access the
	// user's cloud chats or is not their registered current key.
	ImportFailureKeyMismatch ImportFailureReason = "key_mismatch"
	// ImportFailureInternal is the fallback when the cause cannot be
	// mapped to a more specific user-safe reason.
	ImportFailureInternal           ImportFailureReason = "internal"
	ImportFailureRequestTimeout     ImportFailureReason = "request_timeout"
	ImportFailureServiceUnavailable ImportFailureReason = "service_unavailable"
	ImportFailureRateLimited        ImportFailureReason = "rate_limited"
	ImportFailureAuthorization      ImportFailureReason = "authorization_failed"
	ImportFailureExistingChatCheck  ImportFailureReason = "existing_chat_check_failed"
	ImportFailureWorker             ImportFailureReason = "worker_failed"
)

// ImportFailureDetail names the check that rejected an archive. Like the
// reason, it is a fixed code that says which rule fired, never what the
// archive contained, so support can tell a truncated download from a
// wrong file without the enclave logging anything.
type ImportFailureDetail string

// Details for ImportFailureInvalidArchive.
const (
	ImportDetailHashMismatch           ImportFailureDetail = "hash_mismatch"
	ImportDetailCorruptZip             ImportFailureDetail = "corrupt_zip"
	ImportDetailUnsupportedCompression ImportFailureDetail = "unsupported_compression"
	ImportDetailUnsafeEntry            ImportFailureDetail = "unsafe_entry"
	ImportDetailMissingConversations   ImportFailureDetail = "missing_conversations"
	ImportDetailInvalidJSON            ImportFailureDetail = "invalid_json"
	ImportDetailUnexpectedJSON         ImportFailureDetail = "unexpected_json"
	ImportDetailNotZip                 ImportFailureDetail = "not_zip"
	ImportDetailMissingManifest        ImportFailureDetail = "missing_manifest"
	ImportDetailInvalidBackup          ImportFailureDetail = "invalid_backup"
)

// Details for ImportFailureLimitExceeded.
const (
	ImportDetailTooManyEntries       ImportFailureDetail = "too_many_entries"
	ImportDetailTooLarge             ImportFailureDetail = "too_large"
	ImportDetailTooManyConversations ImportFailureDetail = "too_many_conversations"
	ImportDetailTooManyMessages      ImportFailureDetail = "too_many_messages"
	ImportDetailTooManyAttachments   ImportFailureDetail = "too_many_attachments"
)

// importFailureErr tags an error with the reason a job failed. Code that
// knows why it is failing wraps its error so the coordinator does not
// have to string-match.
type importFailureErr struct {
	reason ImportFailureReason
	detail ImportFailureDetail
	err    error
}

func (e *importFailureErr) Error() string { return e.err.Error() }
func (e *importFailureErr) Unwrap() error { return e.err }

// importFailure tags err with reason. An error that already carries a
// tag is returned unchanged so the most specific classification, made
// closest to the cause, survives outer wrapping.
func importFailure(reason ImportFailureReason, err error) error {
	return importFailureWithDetail(reason, "", err)
}

func importFailureWithDetail(reason ImportFailureReason, detail ImportFailureDetail, err error) error {
	if err == nil {
		return nil
	}
	var tagged *importFailureErr
	if errors.As(err, &tagged) {
		return err
	}
	return &importFailureErr{reason: reason, detail: detail, err: err}
}

func invalidArchiveErr(detail ImportFailureDetail, msg string) error {
	return importFailureWithDetail(ImportFailureInvalidArchive, detail, errors.New(msg))
}

func limitExceededErr(detail ImportFailureDetail, msg string) error {
	return importFailureWithDetail(ImportFailureLimitExceeded, detail, errors.New(msg))
}

// classifyParseFailure tags a ParseEach error. Only a parser rejection
// of the root document means the upload is not a valid export; any
// other error originated in the emit callback and is either already
// classified or a service error the coordinator classifies.
func classifyParseFailure(err error) error {
	if errors.Is(err, importer.ErrInvalidExport) {
		// A type error means the file is JSON but not a conversation
		// list, such as user.json or an export manifest.
		detail := ImportDetailInvalidJSON
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			detail = ImportDetailUnexpectedJSON
		}
		return importFailureWithDetail(ImportFailureInvalidArchive, detail, err)
	}
	return err
}

// classifyArchiveReadErr tags ZIP or deflate corruption as an invalid
// archive. Other errors retain their original causes and tags so the
// coordinator can distinguish storage failures from invalid exports.
func classifyArchiveReadErr(err error) error {
	if errors.Is(err, zip.ErrAlgorithm) {
		return importFailureWithDetail(ImportFailureInvalidArchive, ImportDetailUnsupportedCompression, err)
	}
	var corrupt flate.CorruptInputError
	if errors.Is(err, zip.ErrFormat) || errors.Is(err, zip.ErrChecksum) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &corrupt) {
		return importFailureWithDetail(ImportFailureInvalidArchive, ImportDetailCorruptZip, err)
	}
	return err
}

// classifyImportFailure maps a job error to its user-safe reason. Job
// deadline expiry takes precedence, followed by request timeouts.
// Specific source tags and typed service errors take precedence over
// generic fallback tags.
func classifyImportFailure(ctx context.Context, err error) ImportFailureReason {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(context.Cause(ctx), errImportStalled) {
		return ImportFailureTimeout
	}
	var networkErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkErr) && networkErr.Timeout()) {
		return ImportFailureRequestTimeout
	}
	var tagged *importFailureErr
	if errors.As(err, &tagged) && tagged.reason != ImportFailureInternal && tagged.reason != ImportFailureExistingChatCheck {
		return safeImportFailureReason(tagged.reason)
	}
	var appErr *AppError
	if errors.As(err, &appErr) && (appErr.Code == CodeStaleKey || appErr.Code == CodeUnknownKey) {
		return ImportFailureKeyMismatch
	}
	var upstreamErr *controlplane.Error
	var bucketErr *buckets.HTTPError
	var statusCode int
	switch {
	case errors.As(err, &upstreamErr):
		statusCode = upstreamErr.StatusCode
	case errors.As(err, &bucketErr):
		statusCode = bucketErr.StatusCode
	}
	switch statusCode {
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return ImportFailureRequestTimeout
	case http.StatusTooManyRequests:
		return ImportFailureRateLimited
	case http.StatusUnauthorized, http.StatusForbidden:
		return ImportFailureAuthorization
	}
	if statusCode >= http.StatusInternalServerError {
		return ImportFailureServiceUnavailable
	}
	if networkErr != nil || (appErr != nil && appErr.Code == CodeNetwork) {
		return ImportFailureServiceUnavailable
	}
	if tagged != nil {
		return safeImportFailureReason(tagged.reason)
	}
	return ImportFailureInternal
}

// importFailureDetail returns the check behind reason when the error was
// tagged with that same reason. A reason that won over the tag, such as
// a job timeout, has no detail.
func importFailureDetail(err error, reason ImportFailureReason) ImportFailureDetail {
	var tagged *importFailureErr
	if !errors.As(err, &tagged) || tagged.reason != reason {
		return ""
	}
	return safeImportFailureDetail(tagged.detail)
}

func safeImportFailureDetail(detail ImportFailureDetail) ImportFailureDetail {
	switch detail {
	case ImportDetailHashMismatch, ImportDetailCorruptZip, ImportDetailUnsupportedCompression,
		ImportDetailUnsafeEntry, ImportDetailMissingConversations, ImportDetailInvalidJSON,
		ImportDetailUnexpectedJSON, ImportDetailNotZip, ImportDetailMissingManifest,
		ImportDetailInvalidBackup, ImportDetailTooManyEntries, ImportDetailTooLarge,
		ImportDetailTooManyConversations, ImportDetailTooManyMessages, ImportDetailTooManyAttachments:
		return detail
	default:
		return ""
	}
}

func safeImportFailureReason(reason ImportFailureReason) ImportFailureReason {
	switch reason {
	case ImportFailureTimeout, ImportFailureInvalidArchive, ImportFailureLimitExceeded,
		ImportFailureKeyMismatch, ImportFailureRequestTimeout, ImportFailureServiceUnavailable,
		ImportFailureRateLimited, ImportFailureAuthorization, ImportFailureExistingChatCheck,
		ImportFailureWorker:
		return reason
	default:
		return ImportFailureInternal
	}
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
		return "import archive exceeds import limits"
	case ImportFailureKeyMismatch:
		return "import key is not the current key"
	case ImportFailureRequestTimeout:
		return "a request to Tinfoil storage timed out; please retry the import"
	case ImportFailureServiceUnavailable:
		return "Tinfoil could not communicate with its storage service; please retry the import"
	case ImportFailureRateLimited:
		return "Tinfoil storage is limiting requests; please wait and retry the import"
	case ImportFailureAuthorization:
		return "Tinfoil could not authorize access to cloud storage for the import; please retry from a signed-in device"
	case ImportFailureExistingChatCheck:
		return "Tinfoil could not check previously imported chats; the import stopped to avoid duplicates"
	case ImportFailureWorker:
		return "the import worker stopped unexpectedly; please retry the import"
	default:
		return "import failed"
	}
}
