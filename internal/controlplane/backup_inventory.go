package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	BackupInventoryPath     = "/api/sync/backup-inventory"
	MaxBackupInventoryItems = 100000
)

var maxBackupInventoryResponseBytes = 128 << 20

type BackupInventoryItem struct {
	Scope     string  `json:"scope"`
	ID        string  `json:"id"`
	ETag      string  `json:"etag"`
	ProjectID *string `json:"project_id,omitempty"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
}

type BackupInventoryResponse struct {
	CapturedAt string                `json:"captured_at"`
	TotalItems int                   `json:"total_items"`
	Items      []BackupInventoryItem `json:"items"`
}

func (c *Client) BackupInventory(ctx context.Context, jwt, clerkUserID string) (*BackupInventoryResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+BackupInventoryPath, nil)
	if err != nil {
		return nil, err
	}
	c.addAuth(httpReq, jwt, clerkUserID)
	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBackupInventoryResponseBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("controlplane: read backup inventory: %w", err)
	}
	if len(body) > maxBackupInventoryResponseBytes {
		return nil, fmt.Errorf("controlplane: backup inventory exceeds %d bytes", maxBackupInventoryResponseBytes)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, parseBackupInventoryError(resp.StatusCode, body)
	}

	var inventory BackupInventoryResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&inventory); err != nil {
		return nil, fmt.Errorf("controlplane: decode backup inventory: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("controlplane: decode backup inventory: trailing data")
	}
	if err := validateBackupInventory(&inventory); err != nil {
		return nil, err
	}
	sort.Slice(inventory.Items, func(i, j int) bool {
		if inventory.Items[i].Scope != inventory.Items[j].Scope {
			return inventory.Items[i].Scope < inventory.Items[j].Scope
		}
		return inventory.Items[i].ID < inventory.Items[j].ID
	})
	return &inventory, nil
}

func parseBackupInventoryError(status int, body []byte) error {
	var wireError struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &wireError)
	return &Error{StatusCode: status, Code: wireError.Code}
}

func validateBackupInventory(inventory *BackupInventoryResponse) error {
	if inventory.CapturedAt == "" {
		return fmt.Errorf("controlplane: invalid backup inventory captured_at")
	}
	if _, err := time.Parse(time.RFC3339Nano, inventory.CapturedAt); err != nil {
		return fmt.Errorf("controlplane: invalid backup inventory captured_at")
	}
	if inventory.Items == nil {
		return fmt.Errorf("controlplane: invalid backup inventory items")
	}
	if len(inventory.Items) > MaxBackupInventoryItems {
		return fmt.Errorf("controlplane: backup inventory exceeds %d items", MaxBackupInventoryItems)
	}
	if inventory.TotalItems != len(inventory.Items) {
		return fmt.Errorf("controlplane: backup inventory total_items does not match items")
	}

	type inventoryKey struct {
		scope string
		id    string
	}
	seen := make(map[inventoryKey]struct{}, len(inventory.Items))
	for index := range inventory.Items {
		item := &inventory.Items[index]
		if strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.ETag) == "" {
			return fmt.Errorf("controlplane: invalid backup inventory item %d identity", index)
		}
		switch item.Scope {
		case "chat":
			if item.ProjectID != nil && strings.TrimSpace(*item.ProjectID) == "" {
				return fmt.Errorf("controlplane: invalid backup inventory item %d project relationship", index)
			}
		case "project":
			if item.ProjectID != nil {
				return fmt.Errorf("controlplane: invalid backup inventory item %d project relationship", index)
			}
		case "project_document":
			if item.ProjectID == nil || strings.TrimSpace(*item.ProjectID) == "" {
				return fmt.Errorf("controlplane: invalid backup inventory item %d project relationship", index)
			}
		default:
			return fmt.Errorf("controlplane: invalid backup inventory item %d scope", index)
		}
		createdAt, err := time.Parse(time.RFC3339Nano, item.CreatedAt)
		if err != nil {
			return fmt.Errorf("controlplane: invalid backup inventory item %d created_at", index)
		}
		updatedAt, err := time.Parse(time.RFC3339Nano, item.UpdatedAt)
		if err != nil || updatedAt.Before(createdAt) {
			return fmt.Errorf("controlplane: invalid backup inventory item %d updated_at", index)
		}
		key := inventoryKey{scope: item.Scope, id: item.ID}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("controlplane: duplicate backup inventory item %d", index)
		}
		seen[key] = struct{}{}
	}
	return nil
}
