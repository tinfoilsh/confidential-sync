// Package buckets is the sync-enclave's HTTP client for
// buckets.tinfoil.sh. Attachments live in a single Tinfoil-owned
// tenant; per-user separation comes from two layers stacked on top
// of the API key:
//
//  1. The access token (URL path) is the attachment's UUIDv4 id,
//     which carries 122 bits of randomness — globally non-colliding
//     and unguessable to any party that does not already see the
//     controlplane's `chat_attachments.id` column.
//  2. The bytes stored at the slot are an enclave-built v2 envelope
//     (AES-256-GCM under the user's CEK with an AAD that binds
//     `clerk_user_id || chat_id || attachment_id`). Even an attacker
//     who can read the bucket bytes recovers only the sealed
//     envelope; without the user's CEK they cannot open it, and
//     without the matching AAD tuple they cannot move the ciphertext
//     to a different chat or user.
//
// The buckets server still asks for a slot key on `Put`/`Get`, but
// the enclave passes `SentinelSlotKey` — a published all-zeros key —
// so the buckets-side AES layer adds no cryptographic strength on
// top of the in-enclave seal. Doing it this way means the buckets
// operator never sees the user's CEK, and a buckets compromise
// reveals at most one sealed envelope per slot.
package buckets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrNotFound is returned when the requested access token is not
// present in buckets. Callers map this to a 404.
var ErrNotFound = errors.New("buckets: item not found")

// SentinelSlotKey is the all-zeros 32-byte key the enclave hands to
// the buckets server's format-1 layer. The actual confidentiality
// guarantee comes from the in-enclave AES-256-GCM seal under the
// user's CEK (see package doc) — using a published constant for the
// buckets layer keeps the wire surface stable while making the
// security model explicit: the buckets operator is not in the trust
// boundary for attachment plaintext.
var SentinelSlotKey = make([]byte, 32)

// Client talks to buckets.tinfoil.sh on behalf of the enclave.
// Authentication is a single static Tinfoil API key the enclave
// holds; every request is attributed to that key's tenant in R2.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

func NewClient(baseURL, apiKey string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		httpClient: httpClient,
	}
}

// Configured reports whether the client has both a URL and an API
// key. Callers use this to fail fast with a clean 503 when the
// service isn't wired up (local dev, smoke tests).
func (c *Client) Configured() bool {
	return c != nil && c.baseURL != "" && c.apiKey != ""
}

type putRequest struct {
	Value          string   `json:"value"`
	EncryptionKeys []string `json:"encryption_keys"`
	Format         int      `json:"format"`
}

type getResponse struct {
	Value string `json:"value"`
}

// Put stores a value at the given access token, encrypted server-side
// under the supplied 32-byte key. Uses the v1 envelope format so the
// key slot can later be rotated without re-uploading the value.
func (c *Client) Put(ctx context.Context, accessToken string, plaintext, key []byte) error {
	if !c.Configured() {
		return errors.New("buckets: client not configured")
	}
	if len(key) != 32 {
		return fmt.Errorf("buckets: encryption key must be 32 bytes, got %d", len(key))
	}
	body, err := json.Marshal(putRequest{
		Value:          base64.StdEncoding.EncodeToString(plaintext),
		EncryptionKeys: []string{base64.StdEncoding.EncodeToString(key)},
		Format:         1,
	})
	if err != nil {
		return fmt.Errorf("buckets: marshal put: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.itemURL(accessToken), bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.setAuth(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("buckets: put request: %w", err)
	}
	defer resp.Body.Close()
	return c.expectOK(resp)
}

// Get fetches and returns the plaintext for the given access token.
// The supplied key must match one of the slots registered at PUT.
func (c *Client) Get(ctx context.Context, accessToken string, key []byte) ([]byte, error) {
	if !c.Configured() {
		return nil, errors.New("buckets: client not configured")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("buckets: encryption key must be 32 bytes, got %d", len(key))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.itemURL(accessToken), nil)
	if err != nil {
		return nil, err
	}
	c.setAuth(req)
	req.Header.Set("X-Encryption-Key", base64.StdEncoding.EncodeToString(key))
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("buckets: get request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if err := c.expectOK(resp); err != nil {
		return nil, err
	}
	var gr getResponse
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return nil, fmt.Errorf("buckets: decode get: %w", err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(gr.Value)
	if err != nil {
		return nil, fmt.Errorf("buckets: decode value: %w", err)
	}
	return plaintext, nil
}

// Delete removes the item at the given access token. A 404 from
// buckets is treated as success: callers want an idempotent delete
// and the item being already-gone is the desired terminal state.
func (c *Client) Delete(ctx context.Context, accessToken string) error {
	if !c.Configured() {
		return errors.New("buckets: client not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.itemURL(accessToken), nil)
	if err != nil {
		return err
	}
	c.setAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("buckets: delete request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return c.expectOK(resp)
}

func (c *Client) itemURL(accessToken string) string {
	return c.baseURL + "/items/" + accessToken
}

func (c *Client) setAuth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
}

func (c *Client) expectOK(resp *http.Response) error {
	if resp.StatusCode/100 == 2 {
		return nil
	}
	preview, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("buckets: status %d: %s", resp.StatusCode, strings.TrimSpace(string(preview)))
}
