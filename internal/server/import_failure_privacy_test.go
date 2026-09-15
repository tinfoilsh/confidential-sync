package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
)

const privateImportTestText = "private conversation title, message, filename, and key"

type importFailureLogCapture struct {
	mu   sync.Mutex
	text bytes.Buffer
}

func (l *importFailureLogCapture) Infof(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.text, format, args...)
}

func (l *importFailureLogCapture) Errorf(format string, args ...any) {
	l.Infof(format, args...)
}

func (l *importFailureLogCapture) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.String()
}

func TestImportFailureDoesNotExposePrivateErrorDetails(t *testing.T) {
	cases := []struct {
		name   string
		cause  error
		panics bool
		want   ImportFailureReason
	}{
		{"unknown error", errors.New(privateImportTestText), false, ImportFailureInternal},
		{"network error", &net.OpError{Op: "read", Err: errors.New(privateImportTestText)}, false, ImportFailureServiceUnavailable},
		{"upstream error", &controlplane.Error{StatusCode: http.StatusForbidden, Message: privateImportTestText}, false, ImportFailureAuthorization},
		{"worker panic", nil, true, ImportFailureWorker},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			capture := &importFailureLogCapture{}
			f.handler.deps.Logger = capture
			notified := captureImportNotifications(t, f)
			job := stageArchive(t, f, "claude", []byte(`[]`))
			coord := NewImportCoordinator()
			coord.runner = func(_ context.Context, _ Deps, _ Session, job *ImportJobState) error {
				job.setProgress(255, 0, 255)
				if tc.panics {
					panic(privateImportTestText)
				}
				return tc.cause
			}
			snap := runCoordinatorJob(t, f, coord, job)
			if snap.FailureReason != tc.want || snap.Imported != 255 {
				t.Fatalf("unexpected failure snapshot: reason=%s imported=%d", snap.FailureReason, snap.Imported)
			}
			body := notified.single(t)
			if body["failureReason"] != string(tc.want) || body["importedCount"] != float64(255) {
				t.Fatalf("unexpected notification: %v", body)
			}
			for _, value := range []any{importStatusResponse(snap), body, capture.String()} {
				encoded, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(encoded, []byte(privateImportTestText)) {
					t.Fatal("private error details escaped the import worker")
				}
			}
			if !strings.Contains(capture.String(), "reason="+string(tc.want)) {
				t.Fatal("safe failure reason missing from logs")
			}
		})
	}
}

type importProbeErrorTransport struct{ cause error }

func (tr importProbeErrorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, tr.cause
}

func TestPriorImportProbePreservesRequestFailure(t *testing.T) {
	f := newFixture(t)
	cause := context.DeadlineExceeded
	deps := f.handler.deps
	deps.Controlplane = controlplane.NewClient(f.cp.server.URL, &http.Client{
		Transport: importProbeErrorTransport{cause: cause},
	})
	exists, err := priorImportedChatExists(context.Background(), deps, importSession(f), f.userKeyB64, "prior-id")
	if exists || !errors.Is(err, cause) {
		t.Fatalf("probe lost its typed cause: exists=%v err=%v", exists, err)
	}
	if got := classifyImportFailure(context.Background(), err); got != ImportFailureRequestTimeout {
		t.Fatalf("got %s, want request_timeout", got)
	}
}

func TestPriorImportProbePreservesHTTPFailure(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	f.cp.mux.HandleFunc("GET /api/sync/blob/chat/prior-id", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	exists, err := priorImportedChatExists(context.Background(), f.handler.deps, importSession(f), f.userKeyB64, "prior-id")
	var upstream *controlplane.Error
	if exists || !errors.As(err, &upstream) || upstream.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("probe lost upstream status: exists=%v err=%v", exists, err)
	}
	if got := classifyImportFailure(context.Background(), err); got != ImportFailureRateLimited {
		t.Fatalf("got %s, want rate_limited", got)
	}
}

func TestPullItemDoesNotSerializeInternalCause(t *testing.T) {
	encoded, err := json.Marshal(PullItem{ID: "prior-id", Code: CodeNetwork, cause: errors.New(privateImportTestText)})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(privateImportTestText)) || bytes.Contains(encoded, []byte(`"cause"`)) {
		t.Fatal("internal cause was serialized")
	}
}
