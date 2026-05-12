package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/resolver"
)

// Application error codes returned in JSON envelopes. These match the
// reference table in syncplan.md Appendix B and the controlplane's own
// codes so the client sees a consistent vocabulary regardless of which
// service rejected the request.
const (
	CodeStaleKey                  = controlplane.StatusStaleKey
	CodeStaleBlob                 = controlplane.StatusStaleBlob
	CodeSyncConflict              = "SYNC_CONFLICT"
	CodeIdempotencyConflict       = controlplane.StatusIdempotencyConflict
	CodeExistingDataUnderOtherKey = controlplane.StatusExistingDataUnderOtherKey
	CodeUnknownKey                = "UNKNOWN_KEY"
	CodeLegacyBlobNotMigrated     = controlplane.StatusLegacyBlobNotMigrated
	CodeAttestationFailed         = "ATTESTATION_FAILED"
	CodeAuth                      = "AUTH"
	CodeForbidden                 = "FORBIDDEN"
	CodeBadRequest                = "BAD_REQUEST"
	CodeNetwork                   = "NETWORK"
	CodeInternal                  = "INTERNAL"
)

// AppError is the wire representation of a non-2xx response. Extra context
// fields (current_etag, current_key_id, reason) are folded in when relevant.
type AppError struct {
	Status        int    `json:"-"`
	Code          string `json:"code"`
	Message       string `json:"message,omitempty"`
	CurrentKeyID  string `json:"current_key_id,omitempty"`
	CurrentETag   string `json:"current_etag,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

func (a *AppError) Error() string {
	if a == nil {
		return "<nil>"
	}
	if a.Code != "" {
		return a.Code
	}
	if a.Message != "" {
		return a.Message
	}
	return http.StatusText(a.Status)
}

func writeError(w http.ResponseWriter, err error) {
	a := translate(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(a.Status)
	payload := map[string]any{
		"ok":   false,
		"code": a.Code,
	}
	if a.Message != "" {
		payload["message"] = a.Message
	}
	if a.CurrentKeyID != "" {
		payload["current_key_id"] = a.CurrentKeyID
	}
	if a.CurrentETag != "" {
		payload["current_etag"] = a.CurrentETag
	}
	if a.Reason != "" {
		payload["reason"] = a.Reason
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func translate(err error) *AppError {
	var a *AppError
	if errors.As(err, &a) {
		if a.Status == 0 {
			a.Status = http.StatusInternalServerError
		}
		if a.Code == "" {
			a.Code = CodeInternal
		}
		return a
	}
	var cpe *controlplane.Error
	if errors.As(err, &cpe) {
		return &AppError{
			Status:       cpe.StatusCode,
			Code:         normalizeCode(cpe.Code, cpe.StatusCode),
			Message:      cpe.Message,
			CurrentKeyID: cpe.CurrentKeyID,
			CurrentETag:  cpe.CurrentETag,
		}
	}
	if resolver.IsConflict(err) {
		return &AppError{
			Status: http.StatusConflict,
			Code:   CodeSyncConflict,
			Reason: resolver.ConflictReason(err),
		}
	}
	return &AppError{
		Status:  http.StatusInternalServerError,
		Code:    CodeInternal,
		Message: err.Error(),
	}
}

func normalizeCode(code string, status int) string {
	if code != "" {
		return code
	}
	switch status {
	case http.StatusUnauthorized:
		return CodeAuth
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusBadRequest:
		return CodeBadRequest
	case http.StatusGone:
		return CodeLegacyBlobNotMigrated
	}
	return CodeInternal
}

func badRequest(message string) *AppError {
	return &AppError{Status: http.StatusBadRequest, Code: CodeBadRequest, Message: message}
}

func unauthorized(message string) *AppError {
	return &AppError{Status: http.StatusUnauthorized, Code: CodeAuth, Message: message}
}
