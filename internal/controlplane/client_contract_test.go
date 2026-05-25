package controlplane

import "testing"

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
			"HeaderKeyID":         {HeaderKeyID, "X-Key-Id"},
			"HeaderIfMatch":       {HeaderIfMatch, "If-Match"},
			"HeaderIdempotency":   {HeaderIdempotency, "X-Idempotency-Key"},
			"HeaderOperationHash": {HeaderOperationHash, "X-Operation-Hash"},
			"HeaderMessageCount":  {HeaderMessageCount, "X-Message-Count"},
			"HeaderProjectID":     {HeaderProjectID, "X-Project-Id"},
			"HeaderProjectIDSet":  {HeaderProjectIDSet, "X-Project-Id-Set"},
			"HeaderETag":          {HeaderETag, "ETag"},
			"HeaderLegacyClaim":   {HeaderLegacyClaim, "X-Legacy-Claim"},
			"HeaderClerkUserID":   {HeaderClerkUserID, "X-Clerk-User-Id"},
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
	})

	t.Run("wire codes", func(t *testing.T) {
		t.Parallel()
		cases := map[string]struct{ have, want string }{
			"StatusPreconditionRequired":      {StatusPreconditionRequired, "PRECONDITION_REQUIRED"},
			"StatusStaleKey":                  {StatusStaleKey, "STALE_KEY"},
			"StatusStaleBlob":                 {StatusStaleBlob, "STALE_BLOB"},
			"StatusExistingDataUnderOtherKey": {StatusExistingDataUnderOtherKey, "EXISTING_DATA_UNDER_OTHER_KEY"},
			"StatusIdempotencyConflict":       {StatusIdempotencyConflict, "IDEMPOTENCY_CONFLICT"},
		}
		for name, c := range cases {
			if c.have != c.want {
				t.Errorf("%s = %q, want %q", name, c.have, c.want)
			}
		}
	})
}
