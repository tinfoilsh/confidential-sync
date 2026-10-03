package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/envelope"
)

func TestTranslateOversizePlaintextIs413(t *testing.T) {
	err := fmt.Errorf("seal: %w", envelope.ErrPlaintextTooLarge)
	a := translate(err)
	if a.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", a.Status)
	}
	if a.Code != CodePayloadTooLarge {
		t.Fatalf("code = %q, want %q", a.Code, CodePayloadTooLarge)
	}
}

func TestTranslateOtherEnvelopeErrorsStayInternal(t *testing.T) {
	a := translate(envelope.ErrInvalidEnvelope)
	if a.Status != http.StatusInternalServerError || a.Code != CodeInternal {
		t.Fatalf("got %d %q, want 500 INTERNAL", a.Status, a.Code)
	}
}

func TestTranslateMaxBytesErrorIs413(t *testing.T) {
	a := translate(&http.MaxBytesError{Limit: 10})
	if a.Status != http.StatusRequestEntityTooLarge || a.Code != CodePayloadTooLarge {
		t.Fatalf("got %d %q, want 413 %s", a.Status, a.Code, CodePayloadTooLarge)
	}
}

func TestDecodeOversizeBodyIs413NotBadRequest(t *testing.T) {
	body := append([]byte(`{"plaintext":"`), bytes.Repeat([]byte("a"), 64)...)
	body = append(body, []byte(`"}`)...)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	req.Body = http.MaxBytesReader(rec, req.Body, 32)

	var dst struct {
		Plaintext string `json:"plaintext"`
	}
	err := decode(req, &dst)
	var a *AppError
	if !errors.As(err, &a) {
		t.Fatalf("expected AppError, got %T %v", err, err)
	}
	if a.Status != http.StatusRequestEntityTooLarge || a.Code != CodePayloadTooLarge {
		t.Fatalf("got %d %q, want 413 %s", a.Status, a.Code, CodePayloadTooLarge)
	}

	rec = httptest.NewRecorder()
	writeError(rec, err)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("writeError status = %d, want 413", rec.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["code"] != CodePayloadTooLarge {
		t.Fatalf("payload code = %v", payload["code"])
	}
}
