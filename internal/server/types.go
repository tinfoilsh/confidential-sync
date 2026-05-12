package server

// Wire shapes for /v1/* endpoints. Each request type is decoded from the
// JSON body; each response type is encoded into the JSON body. Error
// responses are emitted by writeError and follow the AppError shape.

type PushRequest struct {
	Scope          string         `json:"scope"`
	ID             string         `json:"id,omitempty"`
	Key            string         `json:"key"`         // base64 32-byte raw key
	Plaintext      string         `json:"plaintext"`   // base64 plaintext bytes
	IfMatch        *string        `json:"if_match"`    // ETag CAS; null = create
	IdempotencyKey string         `json:"idempotency_key"`
	ConflictPolicy string         `json:"conflict_policy,omitempty"` // auto_merge|reject|replace_remote
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type PushResponse struct {
	OK    bool   `json:"ok"`
	ETag  string `json:"etag"`
	KeyID string `json:"key_id"`
}

type PullKey struct {
	Key   string `json:"key"`    // base64 32-byte raw key
	KeyID string `json:"key_id"` // optional; enclave verifies/derives
}

type PullRequest struct {
	Scope  string    `json:"scope"`
	IDs    []string  `json:"ids,omitempty"`
	All    bool      `json:"all,omitempty"`
	Cursor string    `json:"cursor,omitempty"`
	Limit  int       `json:"limit,omitempty"`
	Keys   []PullKey `json:"keys"`
}

type PullItem struct {
	ID          string `json:"id"`
	OK          bool   `json:"ok"`
	Plaintext   string `json:"plaintext,omitempty"`
	KeyID       string `json:"key_id,omitempty"`
	ETag        string `json:"etag,omitempty"`
	NeedsRewrap bool   `json:"needs_rewrap,omitempty"`
	Code        string `json:"code,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type PullResponse struct {
	Items      []PullItem `json:"items"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

type ListStatusRequest struct {
	Scope  string `json:"scope"`
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

type ListStatusResponse struct {
	Updates    []ListStatusUpdate `json:"updates"`
	Deletes    []ListStatusDelete `json:"deletes"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type ListStatusUpdate struct {
	ID        string `json:"id"`
	ETag      string `json:"etag"`
	KeyID     string `json:"key_id"`
	UpdatedAt string `json:"updated_at"`
	Cursor    string `json:"cursor,omitempty"`
}

type ListStatusDelete struct {
	ID        string `json:"id"`
	Scope     string `json:"scope"`
	DeletedAt string `json:"deleted_at"`
	Cursor    string `json:"cursor,omitempty"`
}

type DeleteRequest struct {
	Scope          string  `json:"scope"`
	ID             string  `json:"id"`
	IfMatch        *string `json:"if_match"`
	IdempotencyKey string  `json:"idempotency_key"`
	// Key is the user's CEK (base64), required to derive the
	// op-hash subkey per §7.0. Delete carries no body so the
	// canonical tuple's BODY is empty, but the MAC keying still
	// has to use the CEK so the controlplane cannot brute-force
	// the (small) (METHOD, PATH, IF_MATCH, IDEM) space.
	Key string `json:"key"`
}

type OKResponse struct {
	OK bool `json:"ok"`
}

type KeyRegisterRequest struct {
	Key            string                  `json:"key"`
	IfMatch        string                  `json:"if_match"`
	CreatedVia     string                  `json:"created_via"`
	IdempotencyKey string                  `json:"idempotency_key"`
	InitialBundle  *KeyRegisterBundleInput `json:"initial_bundle,omitempty"`
}

type KeyRegisterBundleInput struct {
	CredentialID  string `json:"credential_id"`
	KEKIV         string `json:"kek_iv"`
	EncryptedKeys string `json:"encrypted_keys"`
}

type KeyRegisterResponse struct {
	OK    bool   `json:"ok"`
	KeyID string `json:"key_id"`
}

type AddBundleRequest struct {
	KeyID         string `json:"key_id"`
	CredentialID  string `json:"credential_id"`
	KEKIV         string `json:"kek_iv"`
	EncryptedKeys string `json:"encrypted_keys"`
}

type MigrateRequest struct {
	Scope  string         `json:"scope"`
	IDs    []string       `json:"ids,omitempty"`
	Limit  int            `json:"limit,omitempty"`
	Keys   []PullKey      `json:"keys"`
	Target MigrateTarget  `json:"target"`
}

type MigrateTarget struct {
	Key string `json:"key"`
}

type MigrateResponse struct {
	Migrated           int      `json:"migrated"`
	RetryableRemaining int      `json:"retryable_remaining"`
	BlockedUnmigrated  int      `json:"blocked_unmigrated"`
	Blocked            []string `json:"blocked"`
}

type HealthResponse struct {
	Status string `json:"status"`
	GitSHA string `json:"git_sha,omitempty"`
}
