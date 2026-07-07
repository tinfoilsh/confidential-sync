// Package buckets is the sync-enclave's client for the colocated
// tinfoil-buckets-sidecar, an S3-compatible service that runs on
// enclave loopback. Each user's attachments live under their own
// tenant namespace (`user-<clerkId>/<attId>`):
//
//  1. The access token is the attachment's enclave-minted id,
//     globally non-colliding and unguessable to any party that does
//     not already see the controlplane's `chat_attachments.id`
//     column. It is the S3 object key under the owner's tenant prefix.
//  2. The bytes stored at the slot are sealed by the sidecar under a
//     per-attachment AES-256-GCM key the enclave mints fresh on
//     upload and supplies per request via the X-Tinfoil-Encryption-Key
//     header. The enclave never persists that key itself: it returns
//     the key to the webapp on PUT so the webapp embeds it in the
//     chat JSON (in `attachments[i].encryptionKey`), exactly like the
//     legacy v0/v1 attachment scheme. The chat JSON is sealed under
//     the user's CEK, so the per-attachment keys inherit
//     confidentiality from the chat envelope.
//
// The per-user tenant prefix is not a confidentiality boundary — the
// per-attachment key is — but a storage namespace that scopes every
// read and delete to the owning user, so a forged or mismatched
// attachment id can only ever address the caller's own objects.
//
// The sidecar runs in multitenant mode, which requires every request
// to carry both X-Tinfoil-Tenant-Id and a base64 32-byte
// X-Tinfoil-Encryption-Key. Single deletes carry a throwaway key
// because the resolver mandates the header on every request but never
// uses it to decrypt on that path.
package buckets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ErrNotFound is returned when the requested access token is not
// present in buckets. Callers map this to a 404.
var ErrNotFound = errors.New("buckets: item not found")

// ErrForbidden is returned when the sidecar cannot decrypt the object
// with the supplied key (S3 error code DecryptionFailed).
var ErrForbidden = errors.New("buckets: forbidden")

// ErrTooLarge is returned when a bounded read exceeds the caller's
// maximum accepted response size.
var ErrTooLarge = errors.New("buckets: item too large")

const (
	defaultRequestTimeout = 5 * time.Minute

	// encryptionKeySize is the AES-256 key length the sidecar's
	// multitenant resolver requires; it rejects any key that does not
	// decode to exactly 32 bytes with a 400.
	encryptionKeySize = 32

	// tenantPrefix namespaces every object under the owning user
	// (`user-<clerkId>/<accessToken>`). The combined tenant id must
	// match the sidecar's [A-Za-z0-9_-]{1,64} rule.
	tenantPrefix = "user-"

	headerTenantID      = "X-Tinfoil-Tenant-Id"
	headerEncryptionKey = "X-Tinfoil-Encryption-Key"

	// s3CodeDecryptionFailed is the error code the sidecar returns
	// (with HTTP 400) when the supplied key cannot decrypt the
	// requested object.
	s3CodeDecryptionFailed = "DecryptionFailed"
)

// tenantIDPattern mirrors the sidecar's MultiTenantResolver rule. A
// derived tenant that fails this would be rejected with a 400, so the
// client validates locally and fails loudly instead.
var tenantIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// bucketNamePattern is the modern S3 bucket naming character rule
// (lowercase letters, digits, dots, hyphens; 3-63 chars; starts and
// ends alphanumeric). The bucket becomes a raw path segment of every
// sidecar URL, so anything else (slashes, percent signs, spaces)
// could silently reroute requests instead of failing.
var bucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// ipv4Pattern matches dotted-quad names, which S3 reserves: a bucket
// must not be formatted as an IP address.
var ipv4Pattern = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

// validBucketName applies the S3 naming rules a bucket this client
// can legitimately target must satisfy, so a config typo fails fast
// via Configured instead of reaching the sidecar.
func validBucketName(s string) bool {
	return bucketNamePattern.MatchString(s) &&
		!strings.Contains(s, "..") &&
		!ipv4Pattern.MatchString(s)
}

// deleteKeyPlaceholder satisfies the sidecar's mandatory
// X-Tinfoil-Encryption-Key header on the delete path, which never
// decrypts. The resolver rejects any request whose key does not decode
// to 32 bytes; a fixed all-zero key keeps the id-only delete working
// without a real per-attachment key.
var deleteKeyPlaceholder = make([]byte, encryptionKeySize)

// Client talks to the colocated buckets sidecar over its
// S3-compatible API. No authentication is required: the sidecar runs
// on enclave loopback and authorizes by the per-request tenant id and
// encryption key headers.
type Client struct {
	baseURL    string
	bucket     string
	httpClient *http.Client
}

// NewClient builds a sidecar client. bucket is the S3 bucket the
// sidecar routes to: it honors whatever bucket the request path names
// (path-style `/{bucket}/{key}`), with IAM on the sidecar's
// credentials as the enforcement point for reachability. The value
// comes from deploy config, never user input, and must be a valid S3
// bucket name; Configured rejects anything else so requests are never
// built from a malformed value.
func NewClient(baseURL, bucket string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultRequestTimeout}
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		bucket:     bucket,
		httpClient: httpClient,
	}
}

// Configured reports whether the client has a sidecar URL and a
// valid target bucket. Callers use this to fail fast with a clean 503
// when the service isn't wired up (local dev, smoke tests) or when a
// deploy-config typo would otherwise be interpolated into request
// URLs as a malformed path segment.
func (c *Client) Configured() bool {
	return c != nil && c.baseURL != "" && validBucketName(c.bucket)
}

// Put stores plaintext for owner at the given access token, encrypted
// by the sidecar under the supplied 32-byte key. The body is a single
// path-style S3 PutObject; the sidecar requires Content-Length, which
// the request carries explicitly.
func (c *Client) Put(ctx context.Context, owner, accessToken string, plaintext, key []byte) error {
	if !c.Configured() {
		return errors.New("buckets: client not configured")
	}
	if len(key) != encryptionKeySize {
		return fmt.Errorf("buckets: encryption key must be %d bytes, got %d", encryptionKeySize, len(key))
	}
	tenant, err := tenantForUser(owner)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.objectURL(accessToken), bytes.NewReader(plaintext))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(plaintext))
	req.Header.Set("Content-Type", "application/octet-stream")
	c.setTenantHeaders(req, tenant, key)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("buckets: put request: %w", err)
	}
	defer resp.Body.Close()
	return c.expectOK(resp)
}

// Get fetches and returns the plaintext owner stored at the given
// access token. The supplied key must be the one the object was sealed
// under at PUT.
func (c *Client) Get(ctx context.Context, owner, accessToken string, key []byte) ([]byte, error) {
	return c.GetLimited(ctx, owner, accessToken, key, 0)
}

// GetLimited fetches plaintext like Get, but rejects successful
// responses whose body exceeds maxBytes. A non-positive maxBytes means
// unbounded, matching Get.
func (c *Client) GetLimited(ctx context.Context, owner, accessToken string, key []byte, maxBytes int64) ([]byte, error) {
	if !c.Configured() {
		return nil, errors.New("buckets: client not configured")
	}
	if len(key) != encryptionKeySize {
		return nil, fmt.Errorf("buckets: encryption key must be %d bytes, got %d", encryptionKeySize, len(key))
	}
	tenant, err := tenantForUser(owner)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.objectURL(accessToken), nil)
	if err != nil {
		return nil, err
	}
	c.setTenantHeaders(req, tenant, key)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("buckets: get request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var reader io.Reader = resp.Body
		if maxBytes > 0 {
			reader = io.LimitReader(resp.Body, maxBytes+1)
		}
		plaintext, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("buckets: read get: %w", err)
		}
		if maxBytes > 0 && int64(len(plaintext)) > maxBytes {
			return nil, fmt.Errorf("buckets: get body exceeds %d bytes: %w", maxBytes, ErrTooLarge)
		}
		return plaintext, nil
	case http.StatusNotFound:
		// Drain the body so the HTTP/1.1 connection can be reused;
		// otherwise repeated cache misses keep stacking new TCP
		// connections.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, ErrNotFound
	case http.StatusBadRequest:
		// The only 400 a well-formed GET can trigger is a key/object
		// mismatch (DecryptionFailed); the headers we send are always
		// valid. Confirm the S3 error code before mapping so genuine
		// InvalidArgument bugs aren't silently treated as forbidden.
		code, msg := s3Error(resp.Body)
		if code == s3CodeDecryptionFailed {
			return nil, ErrForbidden
		}
		return nil, fmt.Errorf("buckets: get status 400: %s", joinCodeMessage(code, msg))
	default:
		code, msg := s3Error(resp.Body)
		return nil, fmt.Errorf("buckets: get status %d: %s", resp.StatusCode, joinCodeMessage(code, msg))
	}
}

// Delete removes owner's item at the given access token. A 404 from
// the sidecar is treated as success: callers want an idempotent delete
// and the item being already-gone is the desired terminal state.
func (c *Client) Delete(ctx context.Context, owner, accessToken string) error {
	if !c.Configured() {
		return errors.New("buckets: client not configured")
	}
	tenant, err := tenantForUser(owner)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.objectURL(accessToken), nil)
	if err != nil {
		return err
	}
	c.setTenantHeaders(req, tenant, deleteKeyPlaceholder)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("buckets: delete request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return c.expectOK(resp)
}

func (c *Client) objectURL(accessToken string) string {
	return c.baseURL + "/" + c.bucket + "/" + accessToken
}

func (c *Client) setTenantHeaders(req *http.Request, tenant string, key []byte) {
	req.Header.Set(headerTenantID, tenant)
	req.Header.Set(headerEncryptionKey, base64.StdEncoding.EncodeToString(key))
}

func (c *Client) expectOK(resp *http.Response) error {
	if resp.StatusCode/100 == 2 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	code, msg := s3Error(resp.Body)
	return fmt.Errorf("buckets: status %d: %s", resp.StatusCode, joinCodeMessage(code, msg))
}

// TenantForUser exposes the per-user tenant derivation so test
// harnesses can address objects under the same prefix the client
// uses without duplicating the prefix rule.
func TenantForUser(owner string) (string, error) {
	return tenantForUser(owner)
}

// tenantForUser derives and validates the per-user tenant id. A
// malformed owner (empty, or one that pushes the tenant past the
// sidecar's character/length rule) fails here instead of as an opaque
// 400 from the sidecar.
func tenantForUser(owner string) (string, error) {
	if owner == "" {
		return "", errors.New("buckets: owner is required")
	}
	tenant := tenantPrefix + owner
	if !tenantIDPattern.MatchString(tenant) {
		return "", fmt.Errorf("buckets: owner %q yields invalid tenant id", owner)
	}
	return tenant, nil
}

type s3ErrorBody struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// s3Error reads a bounded S3 XML error body and returns its Code and
// Message. On a body that isn't parseable XML it returns an empty code
// and the trimmed raw text so the caller can still surface something.
func s3Error(r io.Reader) (code, message string) {
	raw, _ := io.ReadAll(io.LimitReader(r, 8192))
	var e s3ErrorBody
	if err := xml.Unmarshal(raw, &e); err == nil && e.Code != "" {
		return e.Code, e.Message
	}
	return "", strings.TrimSpace(string(raw))
}

func joinCodeMessage(code, message string) string {
	switch {
	case code != "" && message != "":
		return code + ": " + message
	case code != "":
		return code
	default:
		return message
	}
}
