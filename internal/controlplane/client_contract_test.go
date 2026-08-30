package controlplane

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// TestWireContractMirrorsControlplane pins every wire-level constant
// declared in client.go to the exact string the controlplane sends
// over the wire. The canonical source of truth lives in
// github.com/tinfoilsh/controlplane/pkg/contract; if a constant
// changes there and this file is not updated to match, this test
// fails so the drift is caught before the enclave is redeployed
// against the new controlplane.
//
// Do not relax these assertions to "constant is non-empty" — the
// whole point is to catch typos. Each row pairs a local constant
// against the literal string expected on the wire.
func TestWireContractMirrorsControlplane(t *testing.T) {
	t.Parallel()

	t.Run("headers", func(t *testing.T) {
		t.Parallel()
		cases := map[string]struct{ have, want string }{
			"HeaderSyncProtocol":        {HeaderSyncProtocol, "X-Sync-Protocol"},
			"HeaderKeyID":               {HeaderKeyID, "X-Key-Id"},
			"HeaderIfMatch":             {HeaderIfMatch, "If-Match"},
			"HeaderIdempotency":         {HeaderIdempotency, "X-Idempotency-Key"},
			"HeaderOperationHash":       {HeaderOperationHash, "X-Operation-Hash"},
			"HeaderProfileSyncProtocol": {HeaderProfileSyncProtocol, "X-Profile-Sync-Protocol"},
			"HeaderMessageCount":        {HeaderMessageCount, "X-Message-Count"},
			"HeaderProjectID":           {HeaderProjectID, "X-Project-Id"},
			"HeaderProjectIDSet":        {HeaderProjectIDSet, "X-Project-Id-Set"},
			"HeaderETag":                {HeaderETag, "ETag"},
			"HeaderRequestID":           {HeaderRequestID, "X-Request-ID"},
			"HeaderSearchIndexFenced":   {HeaderSearchIndexFenced, "X-Search-Index-Fenced"},
			"HeaderLegacyClaim":         {HeaderLegacyClaim, "X-Legacy-Claim"},
			"HeaderClerkUserID":         {HeaderClerkUserID, "X-Clerk-User-Id"},
		}
		for name, c := range cases {
			if c.have != c.want {
				t.Errorf("%s = %q, want %q", name, c.have, c.want)
			}
		}
	})

	t.Run("if-match sentinels", func(t *testing.T) {
		t.Parallel()
		if IfMatchCreateOnly != "0" {
			t.Errorf("IfMatchCreateOnly = %q, want %q", IfMatchCreateOnly, "0")
		}
		if IfMatchAnyKey != "*" {
			t.Errorf("IfMatchAnyKey = %q, want %q", IfMatchAnyKey, "*")
		}
		if SyncProtocolV2 != 2 {
			t.Errorf("SyncProtocolV2 = %d, want 2", SyncProtocolV2)
		}
		if ProfileSyncProtocolV2 != 2 {
			t.Errorf("ProfileSyncProtocolV2 = %d, want 2", ProfileSyncProtocolV2)
		}
	})

	t.Run("wire codes", func(t *testing.T) {
		t.Parallel()
		cases := map[string]struct{ have, want string }{
			"StatusPreconditionRequired":       {StatusPreconditionRequired, "PRECONDITION_REQUIRED"},
			"StatusStaleKey":                   {StatusStaleKey, "STALE_KEY"},
			"StatusStaleBlob":                  {StatusStaleBlob, "STALE_BLOB"},
			"StatusExistingDataUnderOtherKey":  {StatusExistingDataUnderOtherKey, "EXISTING_DATA_UNDER_OTHER_KEY"},
			"StatusIdempotencyConflict":        {StatusIdempotencyConflict, "IDEMPOTENCY_CONFLICT"},
			"StatusSearchIndexConflict":        {StatusSearchIndexConflict, "SEARCH_INDEX_CONFLICT"},
			"StatusProfileSyncUpgradeRequired": {StatusProfileSyncUpgradeRequired, "PROFILE_SYNC_UPGRADE_REQUIRED"},
			"StatusSyncSnapshotRequired":       {StatusSyncSnapshotRequired, "SYNC_SNAPSHOT_REQUIRED"},
		}
		for name, c := range cases {
			if c.have != c.want {
				t.Errorf("%s = %q, want %q", name, c.have, c.want)
			}
		}
	})
}

func TestBackupInventoryContractShape(t *testing.T) {
	projectID := "project-1"
	body, err := json.Marshal(BackupInventoryResponse{
		CapturedAt: "2026-08-30T12:00:00Z",
		TotalItems: 1,
		Items: []BackupInventoryItem{{
			Scope: "project_document", ID: "doc-1", ETag: "etag-1", ProjectID: &projectID,
			CreatedAt: "2026-08-30T10:00:00Z", UpdatedAt: "2026-08-30T11:00:00Z",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(body, &outer); err != nil {
		t.Fatal(err)
	}
	outerKeys := make([]string, 0, len(outer))
	for key := range outer {
		outerKeys = append(outerKeys, key)
	}
	sort.Strings(outerKeys)
	if want := []string{"captured_at", "items", "total_items"}; !reflect.DeepEqual(outerKeys, want) {
		t.Fatalf("outer keys = %v, want %v", outerKeys, want)
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(outer["items"], &items); err != nil {
		t.Fatal(err)
	}
	itemKeys := make([]string, 0, len(items[0]))
	for key := range items[0] {
		itemKeys = append(itemKeys, key)
	}
	sort.Strings(itemKeys)
	if want := []string{"created_at", "etag", "id", "project_id", "scope", "updated_at"}; !reflect.DeepEqual(itemKeys, want) {
		t.Fatalf("item keys = %v, want %v", itemKeys, want)
	}
}
