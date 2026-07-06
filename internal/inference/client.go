// Package inference is the sync-enclave's client for the Tinfoil
// confidential inference service's OpenAI-compatible embeddings API.
// The enclave sends chat text and search queries to an embedding
// model running inside Tinfoil inference enclaves, so plaintext never
// leaves the confidential-computing boundary: it travels from this
// CVM to the inference CVM over TLS and is discarded after the
// vectors are returned.
package inference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultRequestTimeout = 60 * time.Second

	// maxResponseBytes bounds the embeddings response body. A single
	// 768-dim float vector is ~15 KiB of JSON; a full batch of
	// MaxBatchSize inputs stays well under this cap.
	maxResponseBytes = 32 << 20

	// MaxBatchSize caps how many inputs one Embed call sends. The
	// inference service accepts larger batches, but bounding it here
	// keeps request bodies and worst-case latency predictable.
	MaxBatchSize = 64

	embeddingsPath = "/v1/embeddings"
)

// Client calls the embeddings endpoint of an OpenAI-compatible
// inference service (Tinfoil confidential inference in production).
type Client struct {
	baseURL    string
	apiKey     string
	model      string
	httpClient *http.Client
}

func NewClient(baseURL, apiKey, model string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultRequestTimeout}
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		model:      model,
		httpClient: httpClient,
	}
}

// Configured reports whether the client has everything it needs to
// issue embedding requests. Callers use this to gate search features
// with a clean 503 instead of a confusing upstream error.
func (c *Client) Configured() bool {
	return c != nil && c.baseURL != "" && c.apiKey != "" && c.model != ""
}

// Model returns the embedding model identifier. The search index
// records it so a model change invalidates stored vectors instead of
// silently mixing incomparable embedding spaces.
func (c *Client) Model() string {
	if c == nil {
		return ""
	}
	return c.model
}

type embeddingsRequest struct {
	Model          string   `json:"model"`
	Input          []string `json:"input"`
	EncodingFormat string   `json:"encoding_format"`
}

type embeddingsResponse struct {
	Data []struct {
		Index     int       `json:"index"`
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
}

// Embed returns one embedding vector per input, in input order.
func (c *Client) Embed(ctx context.Context, inputs []string) ([][]float32, error) {
	if !c.Configured() {
		return nil, errors.New("inference: client not configured")
	}
	if len(inputs) == 0 {
		return nil, errors.New("inference: no inputs")
	}
	if len(inputs) > MaxBatchSize {
		return nil, fmt.Errorf("inference: batch of %d exceeds limit %d", len(inputs), MaxBatchSize)
	}
	body, err := json.Marshal(embeddingsRequest{
		Model:          c.model,
		Input:          inputs,
		EncodingFormat: "float",
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+embeddingsPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("inference: embeddings request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("inference: read embeddings response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inference: embeddings status %d: %s", resp.StatusCode, truncateForError(raw))
	}
	var parsed embeddingsResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("inference: decode embeddings response: %w", err)
	}
	if len(parsed.Data) != len(inputs) {
		return nil, fmt.Errorf("inference: got %d embeddings for %d inputs", len(parsed.Data), len(inputs))
	}
	out := make([][]float32, len(inputs))
	for _, d := range parsed.Data {
		if d.Index < 0 || d.Index >= len(inputs) {
			return nil, fmt.Errorf("inference: embedding index %d out of range", d.Index)
		}
		if len(d.Embedding) == 0 {
			return nil, errors.New("inference: empty embedding vector")
		}
		if out[d.Index] != nil {
			return nil, fmt.Errorf("inference: duplicate embedding index %d", d.Index)
		}
		out[d.Index] = d.Embedding
	}
	for i, v := range out {
		if v == nil {
			return nil, fmt.Errorf("inference: missing embedding for input %d", i)
		}
	}
	return out, nil
}

func truncateForError(raw []byte) string {
	const maxErrBytes = 512
	s := strings.TrimSpace(string(raw))
	if len(s) > maxErrBytes {
		return s[:maxErrBytes] + "..."
	}
	return s
}
