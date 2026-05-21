package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/bucketstub"
)

// bucketsStub mirrors the subset of buckets.tinfoil.sh that the
// enclave's buckets.Client talks to: a single tenant keyed by API
// key, with POSTs to /put, /get, and /delete. Values are stored
// in-memory along with the encryption keys the caller declared at
// PUT-time, and GET verifies the supplied encryption_key matches one
// of the slots — same model real buckets uses.
type bucketsStub struct {
	t      *testing.T
	apiKey string
	items  *bucketstub.Store
	server *httptest.Server
}

type bucketsItem = bucketstub.Item

func newBucketsStub(t *testing.T) *bucketsStub {
	t.Helper()
	s := &bucketsStub{
		t:      t,
		apiKey: "test-api-key",
	}
	s.items = bucketstub.NewStore(s.apiKey)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /put", s.items.Handle)
	mux.HandleFunc("POST /get", s.items.Handle)
	mux.HandleFunc("POST /delete", s.items.Handle)
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

func (s *bucketsStub) has(token string) bool {
	return s.items.Has(token)
}

func (s *bucketsStub) item(token string) (bucketsItem, bool) {
	return s.items.Item(token)
}
