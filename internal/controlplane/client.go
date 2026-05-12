package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to the controlplane on behalf of an authenticated user.
// Every call forwards the user's JWT verbatim in the Authorization header;
// the enclave does not mint its own credentials.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

const (
	HeaderAuth          = "Authorization"
	HeaderKeyID         = "X-Key-Id"
	HeaderIfMatch       = "If-Match"
	HeaderIdempotency   = "X-Idempotency-Key"
	HeaderOperationHash = "X-Operation-Hash"
	HeaderRewrap        = "X-Rewrap"
	HeaderETag          = "ETag"
	HeaderContentType   = "Content-Type"
)

const (
	StatusStaleKey                    = "STALE_KEY"
	StatusStaleBlob                   = "STALE_BLOB"
	StatusExistingDataUnderOtherKey   = "EXISTING_DATA_UNDER_OTHER_KEY"
	StatusIdempotencyConflict         = "IDEMPOTENCY_CONFLICT"
	StatusLegacyBlobNotMigrated       = "LEGACY_BLOB_NOT_MIGRATED"
)

// Error is a structured error returned from the controlplane. It contains
// the parsed error code plus any contextual fields the controlplane sent.
type Error struct {
	StatusCode    int             `json:"-"`
	Code          string          `json:"code"`
	Message       string          `json:"message,omitempty"`
	CurrentKeyID  string          `json:"current_key_id,omitempty"`
	CurrentETag   string          `json:"current_etag,omitempty"`
	Raw           json.RawMessage `json:"-"`
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Code != "" {
		return fmt.Sprintf("controlplane: %s (status %d)", e.Code, e.StatusCode)
	}
	if e.Message != "" {
		return fmt.Sprintf("controlplane: %s (status %d)", e.Message, e.StatusCode)
	}
	return fmt.Sprintf("controlplane: status %d", e.StatusCode)
}

// BlobMeta describes one row's controlplane-visible metadata. ETag is the
// CAS token; KeyID is the row's last writer's KeyID.
type BlobMeta struct {
	ID        string    `json:"id"`
	ETag      string    `json:"etag"`
	KeyID     string    `json:"key_id"`
	UpdatedAt time.Time `json:"updated_at"`
	Cursor    string    `json:"cursor,omitempty"`
}

type BlobDelete struct {
	ID        string    `json:"id"`
	Scope     string    `json:"scope"`
	DeletedAt time.Time `json:"deleted_at"`
	Cursor    string    `json:"cursor,omitempty"`
}

type ListStatusResponse struct {
	Updates    []BlobMeta   `json:"updates"`
	Deletes    []BlobDelete `json:"deletes"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

type PutBlobRequest struct {
	Scope          string
	ID             string
	JWT            string
	KeyIDHex       string
	IfMatch        string
	IdempotencyKey string
	OperationHash  string
	Rewrap         bool
	Ciphertext     []byte
}

type PutBlobResponse struct {
	ETag  string `json:"etag"`
	KeyID string `json:"key_id"`
}

type GetBlobResponse struct {
	Ciphertext []byte
	ETag       string
	KeyID      string
}

func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("controlplane: request: %w", err)
	}
	return resp, nil
}

func (c *Client) addAuth(req *http.Request, rawJWT string) {
	req.Header.Set(HeaderAuth, "Bearer "+rawJWT)
}

func (c *Client) urlFor(scope, id string) (string, error) {
	path, err := PathFor(scope, id)
	if err != nil {
		return "", err
	}
	return c.baseURL + path, nil
}

// PathFor returns the controlplane path (no scheme/host) for a given
// scope+id. Exported so callers — most importantly the operation-hash
// builder — can produce a canonical tuple that exactly matches what
// will be sent on the wire.
func PathFor(scope, id string) (string, error) {
	switch scope {
	case "chat":
		return "/api/storage/conversation/" + url.PathEscape(id), nil
	case "profile":
		return "/api/profile/", nil
	case "project":
		return "/api/projects/" + url.PathEscape(id), nil
	case "project_document":
		parent, doc, ok := splitProjectDocID(id)
		if !ok {
			return "", fmt.Errorf("controlplane: invalid project_document id %q", id)
		}
		return "/api/projects/" + url.PathEscape(parent) + "/documents/" + url.PathEscape(doc), nil
	}
	return "", fmt.Errorf("controlplane: unknown scope %q", scope)
}

func splitProjectDocID(id string) (parent, doc string, ok bool) {
	idx := strings.Index(id, "/")
	if idx <= 0 || idx == len(id)-1 {
		return "", "", false
	}
	return id[:idx], id[idx+1:], true
}

func (c *Client) PutBlob(ctx context.Context, req PutBlobRequest) (*PutBlobResponse, error) {
	endpoint, err := c.urlFor(req.Scope, req.ID)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(req.Ciphertext))
	if err != nil {
		return nil, err
	}
	c.addAuth(httpReq, req.JWT)
	httpReq.Header.Set(HeaderContentType, "application/octet-stream")
	httpReq.Header.Set(HeaderKeyID, req.KeyIDHex)
	if req.IfMatch != "" {
		httpReq.Header.Set(HeaderIfMatch, req.IfMatch)
	}
	if req.IdempotencyKey != "" {
		httpReq.Header.Set(HeaderIdempotency, req.IdempotencyKey)
	}
	if req.OperationHash != "" {
		httpReq.Header.Set(HeaderOperationHash, req.OperationHash)
	}
	if req.Rewrap {
		httpReq.Header.Set(HeaderRewrap, "true")
	}
	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, parseError(resp.StatusCode, body)
	}
	out := &PutBlobResponse{
		ETag:  resp.Header.Get(HeaderETag),
		KeyID: resp.Header.Get(HeaderKeyID),
	}
	if len(body) > 0 {
		_ = json.Unmarshal(body, out)
	}
	if out.ETag == "" {
		return nil, errors.New("controlplane: missing ETag in PutBlob response")
	}
	if out.KeyID == "" {
		out.KeyID = req.KeyIDHex
	}
	return out, nil
}

func (c *Client) GetBlob(ctx context.Context, scope, id, jwt string) (*GetBlobResponse, error) {
	endpoint, err := c.urlFor(scope, id)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	c.addAuth(httpReq, jwt)
	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, parseError(resp.StatusCode, body)
	}
	return &GetBlobResponse{
		Ciphertext: body,
		ETag:       resp.Header.Get(HeaderETag),
		KeyID:      resp.Header.Get(HeaderKeyID),
	}, nil
}

type DeleteBlobRequest struct {
	Scope          string
	ID             string
	JWT            string
	IfMatch        string
	IdempotencyKey string
	OperationHash  string
}

func (c *Client) DeleteBlob(ctx context.Context, req DeleteBlobRequest) error {
	endpoint, err := c.urlFor(req.Scope, req.ID)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	c.addAuth(httpReq, req.JWT)
	if req.IfMatch != "" {
		httpReq.Header.Set(HeaderIfMatch, req.IfMatch)
	}
	if req.IdempotencyKey != "" {
		httpReq.Header.Set(HeaderIdempotency, req.IdempotencyKey)
	}
	if req.OperationHash != "" {
		httpReq.Header.Set(HeaderOperationHash, req.OperationHash)
	}
	resp, err := c.doRequest(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return parseError(resp.StatusCode, body)
	}
	return nil
}

func (c *Client) ListStatus(ctx context.Context, scope, cursor string, limit int, jwt string) (*ListStatusResponse, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	endpoint := c.baseURL + "/api/sync/list-status"
	q := url.Values{}
	q.Set("scope", scope)
	q.Set("limit", fmt.Sprintf("%d", limit))
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	c.addAuth(httpReq, jwt)
	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, parseError(resp.StatusCode, body)
	}
	var out ListStatusResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("controlplane: decode list-status: %w", err)
	}
	return &out, nil
}

type ListNeedsMigrationResponse struct {
	IDs                 []string `json:"ids"`
	RetryableRemaining  int      `json:"retryable_remaining"`
	BlockedUnmigrated   int      `json:"blocked_unmigrated"`
}

func (c *Client) ListNeedsMigration(ctx context.Context, scope string, limit int, jwt string) (*ListNeedsMigrationResponse, error) {
	endpoint := c.baseURL + "/api/sync/needs-migration"
	q := url.Values{}
	q.Set("scope", scope)
	q.Set("limit", fmt.Sprintf("%d", limit))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	c.addAuth(httpReq, jwt)
	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, parseError(resp.StatusCode, body)
	}
	var out ListNeedsMigrationResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("controlplane: decode needs-migration: %w", err)
	}
	return &out, nil
}

// RecordMigrationFailure tells the controlplane that a migration attempt
// for the given (scope, id) failed because none of the supplied keys could
// decrypt the legacy blob. The controlplane stamps the row with the current
// timestamp so it is excluded from the next batch until the 24h cooldown
// elapses.
func (c *Client) RecordMigrationFailure(ctx context.Context, scope, id, jwt string) error {
	endpoint := c.baseURL + "/api/sync/migration-failure"
	body, _ := json.Marshal(map[string]string{"scope": scope, "id": id})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.addAuth(httpReq, jwt)
	httpReq.Header.Set(HeaderContentType, "application/json")
	resp, err := c.doRequest(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return parseError(resp.StatusCode, respBody)
	}
	return nil
}

// --- key registry ----------------------------------------------------------

type CurrentKeyResponse struct {
	KeyID     string                          `json:"key_id"`
	Bundles   map[string]CurrentKeyBundle     `json:"bundles"`
	CreatedAt time.Time                       `json:"created_at"`
}

type CurrentKeyBundle struct {
	CredentialID  string `json:"credential_id"`
	KEKIV         string `json:"kek_iv"`
	EncryptedKeys string `json:"encrypted_keys"`
	RegisteredAt  time.Time `json:"registered_at"`
}

func (c *Client) GetCurrentKey(ctx context.Context, jwt string) (*CurrentKeyResponse, error) {
	endpoint := c.baseURL + "/api/keys/current"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	c.addAuth(httpReq, jwt)
	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, parseError(resp.StatusCode, body)
	}
	var out CurrentKeyResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("controlplane: decode current-key: %w", err)
	}
	return &out, nil
}

type RegisterKeyRequest struct {
	JWT            string
	KeyIDHex       string
	IfMatch        string
	CreatedVia     string
	IdempotencyKey string
	OperationHash  string
	InitialBundle  *RegisterKeyBundle
}

type RegisterKeyBundle struct {
	CredentialID  string `json:"credential_id"`
	KEKIV         string `json:"kek_iv"`
	EncryptedKeys string `json:"encrypted_keys"`
}

// RegisterKeyBody returns the JSON body bytes that will be sent for the
// given RegisterKey request. Exported so callers can hash the exact
// bytes that go on the wire as part of the §7.0 canonical tuple.
func RegisterKeyBody(req RegisterKeyRequest) ([]byte, error) {
	payload := map[string]any{
		"key_id":      req.KeyIDHex,
		"created_via": req.CreatedVia,
	}
	if req.InitialBundle != nil {
		payload["initial_bundle"] = req.InitialBundle
	}
	return json.Marshal(payload)
}

// RegisterKeyPath is the controlplane path the RegisterKey call targets.
const RegisterKeyPath = "/api/keys"

func (c *Client) RegisterKey(ctx context.Context, req RegisterKeyRequest) error {
	endpoint := c.baseURL + RegisterKeyPath
	body, err := RegisterKeyBody(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.addAuth(httpReq, req.JWT)
	httpReq.Header.Set(HeaderContentType, "application/json")
	if req.IfMatch != "" {
		httpReq.Header.Set(HeaderIfMatch, req.IfMatch)
	}
	if req.IdempotencyKey != "" {
		httpReq.Header.Set(HeaderIdempotency, req.IdempotencyKey)
	}
	if req.OperationHash != "" {
		httpReq.Header.Set(HeaderOperationHash, req.OperationHash)
	}
	resp, err := c.doRequest(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return parseError(resp.StatusCode, respBody)
	}
	return nil
}

type AddBundleRequest struct {
	JWT           string
	KeyIDHex      string
	CredentialID  string
	KEKIV         string
	EncryptedKeys string
}

func (c *Client) AddBundle(ctx context.Context, req AddBundleRequest) error {
	endpoint := c.baseURL + "/api/keys/" + url.PathEscape(req.KeyIDHex) + "/bundles"
	body, err := json.Marshal(map[string]string{
		"credential_id":  req.CredentialID,
		"kek_iv":         req.KEKIV,
		"encrypted_keys": req.EncryptedKeys,
	})
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.addAuth(httpReq, req.JWT)
	httpReq.Header.Set(HeaderContentType, "application/json")
	resp, err := c.doRequest(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return parseError(resp.StatusCode, respBody)
	}
	return nil
}

func parseError(status int, body []byte) error {
	if len(body) == 0 {
		return &Error{StatusCode: status}
	}
	var e Error
	if err := json.Unmarshal(body, &e); err != nil {
		return &Error{StatusCode: status, Message: string(body), Raw: body}
	}
	e.StatusCode = status
	e.Raw = body
	return &e
}

// IsCode reports whether err is a controlplane error with the given code.
func IsCode(err error, code string) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	return e.Code == code
}
