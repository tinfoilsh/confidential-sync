// Package buckets is the sync-enclave's HTTP client for
// buckets.tinfoil.sh. Attachments live in a single Tinfoil-owned
// tenant; per-user separation comes from two layers stacked on top
// of the API key:
//
//  1. The access token is the attachment's enclave-minted id,
//     globally non-colliding and unguessable to any party that does
//     not already see the controlplane's `chat_attachments.id`
//     column.
//  2. The bytes stored at the slot are sealed by buckets under a
//     per-attachment AES-256-GCM key the enclave mints fresh on
//     upload. The enclave never persists that key itself: it
//     returns the key to the webapp on PUT so the webapp embeds it
//     in the chat JSON (in `attachments[i].encryptionKey`), exactly
//     like the legacy v0/v1 attachment scheme. The chat JSON is
//     sealed under the user's CEK, so the per-attachment keys
//     inherit confidentiality from the chat envelope.
//
// Because the per-attachment key lives in the chat JSON, sharing
// works out of the box: re-sealing only the chat plaintext under a
// fresh share key automatically grants the recipient access to all
// the attachment keys without re-encrypting any blob.
package buckets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ErrNotFound is returned when the requested access token is not
// present in buckets. Callers map this to a 404.
var ErrNotFound = errors.New("buckets: item not found")

// ErrForbidden is returned when buckets rejects the supplied slot key.
var ErrForbidden = errors.New("buckets: forbidden")

const defaultRequestTimeout = 5 * time.Minute

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
		httpClient = &http.Client{Timeout: defaultRequestTimeout}
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

type getRequest struct {
	AccessToken   string `json:"access_token"`
	EncryptionKey string `json:"encryption_key"`
}

type accessTokenRequest struct {
	AccessToken string `json:"access_token"`
}

type putResponse struct {
	PlaintextLength int64  `json:"plaintext_length"`
	Version         int64  `json:"version"`
	CreatedAt       string `json:"created_at"`
}

// Put stores a value at the given access token, encrypted server-side
// under the supplied 32-byte key.
func (c *Client) Put(ctx context.Context, accessToken string, plaintext, key []byte) error {
	if !c.Configured() {
		return errors.New("buckets: client not configured")
	}
	if len(key) != 32 {
		return fmt.Errorf("buckets: encryption key must be 32 bytes, got %d", len(key))
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("access_token", accessToken); err != nil {
		return fmt.Errorf("buckets: write access token: %w", err)
	}
	if err := writer.WriteField("encryption_keys", base64.StdEncoding.EncodeToString(key)); err != nil {
		return fmt.Errorf("buckets: write encryption key: %w", err)
	}
	if err := writer.WriteField("plaintext_length", strconv.Itoa(len(plaintext))); err != nil {
		return fmt.Errorf("buckets: write plaintext length: %w", err)
	}
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		return fmt.Errorf("buckets: create data field: %w", err)
	}
	if _, err := dataPart.Write(plaintext); err != nil {
		return fmt.Errorf("buckets: write data: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("buckets: close multipart: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpointURL("/put"), &body)
	if err != nil {
		return err
	}
	c.setAuth(req)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("buckets: put request: %w", err)
	}
	defer resp.Body.Close()
	if err := c.expectOK(resp); err != nil {
		return err
	}
	var pr putResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return fmt.Errorf("buckets: decode put: %w", err)
	}
	if pr.PlaintextLength != int64(len(plaintext)) {
		return fmt.Errorf("buckets: put length mismatch: got %d, want %d", pr.PlaintextLength, len(plaintext))
	}
	return nil
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
	body, err := json.Marshal(getRequest{
		AccessToken:   accessToken,
		EncryptionKey: base64.StdEncoding.EncodeToString(key),
	})
	if err != nil {
		return nil, fmt.Errorf("buckets: marshal get: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpointURL("/get"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.setAuth(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("buckets: get request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// Drain the 404 body so the HTTP/1.1 connection can be
		// reused; otherwise repeated cache misses keep stacking
		// new TCP connections.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, ErrNotFound
	}
	if resp.StatusCode == http.StatusForbidden {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, ErrForbidden
	}
	if err := c.expectOK(resp); err != nil {
		return nil, err
	}
	plaintext, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("buckets: read get: %w", err)
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
	body, err := json.Marshal(accessTokenRequest{AccessToken: accessToken})
	if err != nil {
		return fmt.Errorf("buckets: marshal delete: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpointURL("/delete"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.setAuth(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("buckets: delete request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := c.expectOK(resp); err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *Client) endpointURL(path string) string {
	return c.baseURL + path
}

func (c *Client) setAuth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
}

func (c *Client) expectOK(resp *http.Response) error {
	if resp.StatusCode/100 == 2 {
		return nil
	}
	preview, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_, _ = io.Copy(io.Discard, resp.Body)
	return fmt.Errorf("buckets: status %d: %s", resp.StatusCode, strings.TrimSpace(string(preview)))
}
