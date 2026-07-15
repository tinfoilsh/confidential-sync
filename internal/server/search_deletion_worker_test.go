package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
)

func TestSweepSearchIndexDeletionsDeletesAndAcknowledges(t *testing.T) {
	bucketStub := newBucketsStub(t)
	bucketClient := buckets.NewClient(bucketStub.server.URL, testBucketName, nil)
	key := make([]byte, 32)
	if err := bucketClient.Put(context.Background(), "user-1", "object-1", []byte("index"), key); err != nil {
		t.Fatal(err)
	}

	var acked []string
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/sync/search-index-deletions/claim":
			_, _ = w.Write([]byte(`{"claim_token":"claim-1","deletions":[{"id":"row-1","clerk_user_id":"user-1","object_key":"object-1"},{"id":"row-2","clerk_user_id":"user-1","object_key":"already-missing"}]}`))
		case "/api/sync/search-index-deletions/ack":
			var body struct {
				ClaimToken string   `json:"claim_token"`
				IDs        []string `json:"ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.ClaimToken != "claim-1" {
				t.Errorf("claim token: %q", body.ClaimToken)
			}
			acked = body.IDs
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cp.Close)

	count, err := sweepSearchIndexDeletions(context.Background(), Deps{
		Controlplane:  controlplane.NewClient(cp.URL, nil),
		SearchBuckets: bucketClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || len(acked) != 2 {
		t.Fatalf("count=%d acked=%v", count, acked)
	}
	if bucketStub.has("object-1") {
		t.Fatal("search index object was not deleted")
	}
}

func TestSweepSearchIndexDeletionsLeavesFailedDeleteUnacked(t *testing.T) {
	bucketServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(bucketServer.Close)

	acked := false
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/sync/search-index-deletions/claim":
			_, _ = w.Write([]byte(`{"claim_token":"claim-1","deletions":[{"id":"row-1","clerk_user_id":"user-1","object_key":"object-1"}]}`))
		case "/api/sync/search-index-deletions/ack":
			acked = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cp.Close)

	count, err := sweepSearchIndexDeletions(context.Background(), Deps{
		Controlplane:  controlplane.NewClient(cp.URL, nil),
		SearchBuckets: buckets.NewClient(bucketServer.URL, testBucketName, nil),
	})
	if err == nil {
		t.Fatal("expected bucket delete failure")
	}
	if count != 0 || acked {
		t.Fatalf("count=%d acked=%t", count, acked)
	}
}
