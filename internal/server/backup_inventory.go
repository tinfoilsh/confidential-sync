package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
)

const (
	BackupInventoryCacheControl    = "no-store"
	MaxBackupInventoryRequestBytes = 1024
)

type BackupInventoryRequest struct{}

func (*BackupInventoryRequest) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("backup inventory request must be an empty JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &fields); err != nil {
		return err
	}
	if len(fields) != 0 {
		return errors.New("backup inventory request must be an empty JSON object")
	}
	return nil
}

func withBackupInventoryNoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", BackupInventoryCacheControl)
		next.ServeHTTP(w, r)
	})
}

type BackupInventoryResponse = controlplane.BackupInventoryResponse
type BackupInventoryItem = controlplane.BackupInventoryItem

func BackupInventory(ctx context.Context, deps Deps, sess Session, _ BackupInventoryRequest) (*BackupInventoryResponse, error) {
	return deps.Controlplane.BackupInventory(ctx, sess.RawJWT, sess.Claims.Subject)
}
