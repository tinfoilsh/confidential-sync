package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/bucketstub"
)

// bucketsStub mirrors the subset of the colocated buckets sidecar
// that the enclave's buckets.Client talks to: path-style object
// PUT/GET/DELETE plus ListObjectsV2 and bulk delete, namespaced by the
// X-Tinfoil-Tenant-Id header. Values are stored in-memory along with
// the encryption key the caller declared at PUT-time, and GET verifies
// the supplied key matches — same model the real sidecar uses.
type bucketsStub struct {
	t      *testing.T
	items  *bucketstub.Store
	server *httptest.Server
}

type bucketsItem = bucketstub.Item

func newBucketsStub(t *testing.T) *bucketsStub {
	t.Helper()
	s := &bucketsStub{
		t: t,
	}
	s.items = bucketstub.NewStore()
	mux := http.NewServeMux()
	mux.HandleFunc("/bucket/{key}", s.items.Handle)
	mux.HandleFunc("/bucket", s.items.Handle)
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
