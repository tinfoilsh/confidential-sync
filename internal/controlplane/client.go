package controlplane

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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
	HeaderMessageCount  = "X-Message-Count"
	HeaderProjectID     = "X-Project-Id"
	HeaderProjectIDSet  = "X-Project-Id-Set"
	HeaderETag          = "ETag"
	HeaderContentType   = "Content-Type"
)

const (
	StatusStaleKey                  = "STALE_KEY"
	StatusStaleBlob                 = "STALE_BLOB"
	StatusExistingDataUnderOtherKey = "EXISTING_DATA_UNDER_OTHER_KEY"
	StatusIdempotencyConflict       = "IDEMPOTENCY_CONFLICT"
	StatusLegacyBlobNotMigrated     = "LEGACY_BLOB_NOT_MIGRATED"
)

// maxLegacyAttachmentBytes caps the body read for legacy attachment
// downloads. var (not const) so package tests can shrink it to keep
// oversized-body regressions cheap to exercise.
var maxLegacyAttachmentBytes = 64 << 20

// Error is a structured error returned from the controlplane. It contains
// the parsed error code plus any contextual fields the controlplane sent.
type Error struct {
	StatusCode   int             `json:"-"`
	Code         string          `json:"code"`
	Message      string          `json:"message,omitempty"`
	CurrentKeyID string          `json:"current_key_id,omitempty"`
	CurrentETag  string          `json:"current_etag,omitempty"`
	Raw          json.RawMessage `json:"-"`
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
// CAS token; KeyID is the row's last writer's KeyID. ProjectID is a
// chat-scope side-channel that lets clients observe cross-project moves
// without decrypting the row.
type BlobMeta struct {
	ID        string    `json:"id"`
	ETag      string    `json:"etag"`
	KeyID     string    `json:"key_id"`
	ProjectID *string   `json:"project_id,omitempty"`
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
	// MessageCount is forwarded as X-Message-Count for chat scope so
	// the controlplane can persist the legacy column. Nil for scopes
	// other than chat and for rewrap.
	MessageCount *int
	// ProjectIDSet means "overwrite the controlplane's project_id
	// column with ProjectID". When ProjectIDSet is false the column
	// is left untouched. Nil ProjectID + ProjectIDSet=true clears
	// the column. Only meaningful for chat scope.
	ProjectIDSet bool
	ProjectID    *string
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
//
// All blob traffic lives under /api/sync/blob/* — a dedicated surface
// for the enclave that does not overlap with the legacy /api/storage/*
// and /api/profile/* endpoints the webapp drives directly today.
func PathFor(scope, id string) (string, error) {
	switch scope {
	case "chat":
		return "/api/sync/blob/chat/" + url.PathEscape(id), nil
	case "profile":
		return "/api/sync/blob/profile", nil
	case "project":
		return "/api/sync/blob/project/" + url.PathEscape(id), nil
	case "project_document":
		parent, doc, ok := splitProjectDocID(id)
		if !ok {
			return "", fmt.Errorf("controlplane: invalid project_document id %q", id)
		}
		return "/api/sync/blob/project_document/" + url.PathEscape(parent) + "/" + url.PathEscape(doc), nil
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
	if req.Rewrap {
		return c.rewrapBlob(ctx, req)
	}
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
	if req.MessageCount != nil {
		httpReq.Header.Set(HeaderMessageCount, strconv.Itoa(*req.MessageCount))
	}
	if req.ProjectIDSet {
		httpReq.Header.Set(HeaderProjectIDSet, "1")
		if req.ProjectID != nil {
			httpReq.Header.Set(HeaderProjectID, *req.ProjectID)
		}
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

// rewrapBlob targets the dedicated /api/sync/rewrap endpoint. Unlike
// PutBlob's primary path, rewrap is a JSON POST with the ciphertext
// base64-encoded inside the body. The controlplane handler updates
// the row's `data` + `key_id` + `etag` without bumping `sync_version`
// or `updated_at` — a rewrap is invisible to user-facing sync.
// RewrapPath is the controlplane path for the dedicated rewrap
// endpoint. Exported so the enclave can hash the same canonical path
// when computing X-Operation-Hash.
const RewrapPath = "/api/sync/rewrap"

// RewrapBody marshals the body the rewrap call sends to the
// controlplane. Exported so the enclave can compute X-Operation-Hash
// over exactly the bytes that will hit the wire.
func RewrapBody(req PutBlobRequest) ([]byte, error) {
	return json.Marshal(map[string]string{
		"scope":          req.Scope,
		"id":             req.ID,
		"key_id":         req.KeyIDHex,
		"if_match":       req.IfMatch,
		"ciphertext_b64": base64.StdEncoding.EncodeToString(req.Ciphertext),
	})
}

func (c *Client) rewrapBlob(ctx context.Context, req PutBlobRequest) (*PutBlobResponse, error) {
	body, err := RewrapBody(req)
	if err != nil {
		return nil, err
	}
	endpoint := c.baseURL + RewrapPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.addAuth(httpReq, req.JWT)
	httpReq.Header.Set(HeaderContentType, "application/json")
	if req.IdempotencyKey != "" {
		httpReq.Header.Set(HeaderIdempotency, req.IdempotencyKey)
	}
	if req.OperationHash != "" {
		httpReq.Header.Set(HeaderOperationHash, req.OperationHash)
	}
	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, parseError(resp.StatusCode, respBody)
	}
	var out struct {
		OK    bool   `json:"ok"`
		ETag  string `json:"etag"`
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("controlplane: decode rewrap: %w", err)
	}
	if out.ETag == "" {
		return nil, errors.New("controlplane: missing etag in rewrap response")
	}
	if out.KeyID == "" {
		out.KeyID = req.KeyIDHex
	}
	return &PutBlobResponse{ETag: out.ETag, KeyID: out.KeyID}, nil
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

// DeleteBlobResponse mirrors the controlplane's `writeDeleteResponse*`
// shape. For chat deletes the controlplane returns the v2 attachment
// ids it dropped, so the enclave can wipe the matching buckets blobs.
// For non-chat scopes the field is empty.
type DeleteBlobResponse struct {
	OK                 bool     `json:"ok"`
	WipedV2Attachments []string `json:"wiped_v2_attachments,omitempty"`
}

func (c *Client) DeleteBlob(ctx context.Context, req DeleteBlobRequest) (*DeleteBlobResponse, error) {
	endpoint, err := c.urlFor(req.Scope, req.ID)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, parseError(resp.StatusCode, body)
	}
	out := &DeleteBlobResponse{}
	if len(body) > 0 {
		// The controlplane may return an empty body on older
		// deploys; treat that as a successful no-attachments delete
		// rather than an error.
		if err := json.Unmarshal(body, out); err != nil {
			return nil, fmt.Errorf("controlplane: decode delete response: %w", err)
		}
	}
	return out, nil
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
	IDs                []string `json:"ids"`
	RetryableRemaining int      `json:"retryable_remaining"`
	BlockedUnmigrated  int      `json:"blocked_unmigrated"`
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
	KeyID      string                      `json:"key_id"`
	ETag       string                      `json:"etag"`
	Bundles    map[string]CurrentKeyBundle `json:"bundles"`
	CreatedVia string                      `json:"created_via"`
	CreatedAt  time.Time                   `json:"created_at"`
}

type CurrentKeyBundle struct {
	CredentialID  string    `json:"credential_id"`
	KEKIV         string    `json:"kek_iv"`
	EncryptedKeys string    `json:"encrypted_keys"`
	RegisteredAt  time.Time `json:"registered_at"`
}

func (c *Client) GetCurrentKey(ctx context.Context, jwt string) (*CurrentKeyResponse, error) {
	endpoint := c.baseURL + "/api/sync/keys/current"
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
const RegisterKeyPath = "/api/sync/keys"

// RegisterKeyResponse mirrors the wire body the controlplane emits on
// a successful `POST /api/sync/keys`. `WipedV2Attachments` is
// populated only when the call hit the start-fresh bypass; on every
// other path it is nil/empty.
type RegisterKeyResponse struct {
	OK                 bool     `json:"ok"`
	KeyID              string   `json:"key_id"`
	ETag               string   `json:"etag"`
	WipedV2Attachments []string `json:"wiped_v2_attachments,omitempty"`
}

func (c *Client) RegisterKey(ctx context.Context, req RegisterKeyRequest) (*RegisterKeyResponse, error) {
	endpoint := c.baseURL + RegisterKeyPath
	body, err := RegisterKeyBody(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
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
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, parseError(resp.StatusCode, respBody)
	}
	out := &RegisterKeyResponse{}
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return nil, fmt.Errorf("controlplane: decode register-key response: %w", err)
		}
	}
	return out, nil
}

type AddBundleRequest struct {
	JWT            string
	KeyIDHex       string
	CredentialID   string
	KEKIV          string
	EncryptedKeys  string
	IdempotencyKey string
	OperationHash  string
}

// AddBundleBody marshals the body of an add-bundle request. Exposed so
// the enclave can hash exactly what will hit the wire when computing
// X-Operation-Hash.
func AddBundleBody(req AddBundleRequest) ([]byte, error) {
	return json.Marshal(map[string]string{
		"credential_id":  req.CredentialID,
		"kek_iv":         req.KEKIV,
		"encrypted_keys": req.EncryptedKeys,
	})
}

// AddBundlePath is the controlplane path for the add-bundle endpoint.
// Used by the enclave to keep the op-hash canonical path aligned
// with the actual wire path.
func AddBundlePath(keyIDHex string) string {
	return "/api/sync/keys/" + url.PathEscape(keyIDHex) + "/bundles"
}

func (c *Client) AddBundle(ctx context.Context, req AddBundleRequest) error {
	endpoint := c.baseURL + AddBundlePath(req.KeyIDHex)
	body, err := AddBundleBody(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.addAuth(httpReq, req.JWT)
	httpReq.Header.Set(HeaderContentType, "application/json")
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

type RemoveBundleRequest struct {
	JWT            string
	KeyIDHex       string
	CredentialID   string
	IdempotencyKey string
	OperationHash  string
}

// RemoveBundlePath returns the canonical wire path for a remove-bundle
// request so callers can compute the op-hash over the same string.
func RemoveBundlePath(keyIDHex, credentialID string) string {
	return "/api/sync/keys/" + url.PathEscape(keyIDHex) + "/bundles/" + url.PathEscape(credentialID)
}

func (c *Client) RemoveBundle(ctx context.Context, req RemoveBundleRequest) error {
	endpoint := c.baseURL + RemoveBundlePath(req.KeyIDHex, req.CredentialID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	c.addAuth(httpReq, req.JWT)
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

// GetLegacyAttachment fetches the raw ciphertext for a v0/v1
// attachment from controlplane's BYTEA-backed storage. Used by the
// rewrap path to migrate attachments into buckets.tinfoil.sh: the
// enclave reads the ciphertext, decrypts it with the per-attachment
// key embedded in the chat JSON, re-uploads through buckets, and
// then registers a v2 index row (which nulls the BYTEA column).
// A 404 surfaces as ErrLegacyAttachmentNotFound so the caller can
// treat already-migrated rows as a no-op.
var ErrLegacyAttachmentNotFound = errors.New("controlplane: legacy attachment not found")

func (c *Client) GetLegacyAttachment(ctx context.Context, jwt, attachmentID string) ([]byte, error) {
	if attachmentID == "" {
		return nil, fmt.Errorf("controlplane: attachment id is required")
	}
	endpoint := c.baseURL + "/api/storage/attachment/" + url.PathEscape(attachmentID)
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
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrLegacyAttachmentNotFound
	}
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, parseError(resp.StatusCode, raw)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxLegacyAttachmentBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxLegacyAttachmentBytes {
		return nil, fmt.Errorf("controlplane: legacy attachment exceeds %d bytes", maxLegacyAttachmentBytes)
	}
	return body, nil
}

// RegisterAttachmentIndex records ownership of a v2 attachment with
// controlplane. The ciphertext itself lives in buckets.tinfoil.sh
// under a path the enclave derived from (CEK, attachmentID); the
// controlplane only learns "this attachment id exists for this chat,
// owned by this user, in v2 format." JWT is forwarded so the
// controlplane resolves the user from claims, exactly like every
// other sync route.
func (c *Client) RegisterAttachmentIndex(ctx context.Context, jwt, attachmentID, chatID string) error {
	if attachmentID == "" {
		return fmt.Errorf("controlplane: attachment id is required")
	}
	if chatID == "" {
		return fmt.Errorf("controlplane: chat id is required")
	}
	body, err := json.Marshal(struct {
		ChatID string `json:"chat_id"`
	}{ChatID: chatID})
	if err != nil {
		return fmt.Errorf("controlplane: marshal attachment index: %w", err)
	}
	endpoint := c.baseURL + "/api/sync/attachment-index/" + url.PathEscape(attachmentID)
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
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return parseError(resp.StatusCode, raw)
	}
	// Drain the success body so the HTTP/1.1 connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *Client) DeleteAttachmentIndex(ctx context.Context, jwt, attachmentID string) error {
	if attachmentID == "" {
		return fmt.Errorf("controlplane: attachment id is required")
	}
	endpoint := c.baseURL + "/api/sync/attachment-index/" + url.PathEscape(attachmentID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	c.addAuth(httpReq, jwt)
	resp, err := c.doRequest(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_, _ = io.Copy(io.Discard, resp.Body)
		return parseError(resp.StatusCode, raw)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
