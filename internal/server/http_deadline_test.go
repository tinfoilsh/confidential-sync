package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
)

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	readDeadline time.Time
}

func (w *deadlineRecorder) SetReadDeadline(deadline time.Time) error {
	w.readDeadline = deadline
	return nil
}

func TestRequestDeadlineSharedByBodyAndHandler(t *testing.T) {
	f := newFixture(t)
	token := f.jwt()
	for _, authenticated := range []bool{false, true} {
		for _, parentBudget := range []time.Duration{time.Second, time.Hour} {
			t.Run(fmt.Sprintf("authenticated=%t/parent=%s", authenticated, parentBudget), func(t *testing.T) {
				parent, cancel := context.WithTimeout(t.Context(), parentBudget)
				defer cancel()
				parentDeadline, _ := parent.Deadline()
				req := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(parent)
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set(controlplane.HeaderSyncProtocol, "3")
				w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
				var handlerDeadline time.Time
				next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					handlerDeadline, _ = r.Context().Deadline()
				})
				handler := withRequestTimeout(next, StandardRequestTimeout)
				if authenticated {
					handler = f.handler.authMiddleware(func(w http.ResponseWriter, r *http.Request, _ Session) {
						next.ServeHTTP(w, r)
					})
				}
				started := time.Now()
				handler.ServeHTTP(w, req)
				if handlerDeadline.IsZero() || !handlerDeadline.Equal(w.readDeadline) {
					t.Fatalf("handler deadline %s, body deadline %s (response %d)", handlerDeadline, w.readDeadline, w.Code)
				}
				if parentBudget < StandardRequestTimeout {
					if !handlerDeadline.Equal(parentDeadline) {
						t.Fatalf("extended parent deadline %s to %s", parentDeadline, handlerDeadline)
					}
				} else if handlerDeadline.Before(started.Add(StandardRequestTimeout)) || handlerDeadline.After(time.Now().Add(StandardRequestTimeout)) {
					t.Fatalf("deadline %s does not use the route budget", handlerDeadline)
				}
			})
		}
	}
}

// Exercise real socket reads, rather than a body reader that observes the
// context itself. These are streamed requests at the application boundary;
// browser uploads arrive here only after their single EHBP chunk is decrypted.
func TestRouteBodyReadDeadline(t *testing.T) {
	for _, expires := range []bool{false, true} {
		t.Run(fmt.Sprintf("parentExpires=%t", expires), func(t *testing.T) {
			f := newFixture(t)
			const attID = "123e4567-e89b-12d3-a456-426614174111"
			tenant, err := buckets.TenantForUser(f.userSub)
			if err != nil {
				t.Fatal(err)
			}
			f.bk.items.Put(attID, bucketsItem{Tenant: tenant, Value: []byte("payload"), EncryptionKeys: [][]byte{bytes.Repeat([]byte{1}, 32)}})
			f.cp.mu.Lock()
			f.cp.attachmentIndex = map[string]string{attID: "chat-1"}
			f.cp.mu.Unlock()
			routes := f.handler.Routes()
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if expires {
					ctx, cancel := context.WithTimeout(r.Context(), 250*time.Millisecond)
					defer cancel()
					r = r.WithContext(ctx)
				}
				routes.ServeHTTP(w, r)
			}))
			srv.Config.ReadTimeout = 200 * time.Millisecond
			if expires {
				srv.Config.ReadTimeout = 5 * time.Second
			}
			srv.Start()
			defer srv.Close()
			conn, err := net.DialTimeout("tcp", strings.TrimPrefix(srv.URL, "http://"), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			body := `{"id":"` + attID + `"}`
			half := len(body) / 2
			if _, err := fmt.Fprintf(conn, "POST /v1/attachment/delete HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n%s: 3\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", f.jwt(), controlplane.HeaderSyncProtocol, len(body), body[:half]); err != nil {
				t.Fatal(err)
			}
			if !expires {
				// Finish after the server fallback, but within the route budget.
				<-time.After(2 * srv.Config.ReadTimeout)
				if _, err := io.WriteString(conn, body[half:]); err != nil {
					t.Fatal(err)
				}
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("route did not answer within the test deadline: %v", err)
			}
			defer resp.Body.Close()
			response, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if expires {
				var failure AppError
				if err := json.Unmarshal(response, &failure); err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != http.StatusBadRequest || failure.Code != CodeBadRequest {
					t.Fatalf("blocked read: %d %s", resp.StatusCode, response)
				}
				item, exists := f.bk.item(attID)
				if !exists || string(item.Value) != "payload" {
					t.Fatal("incomplete request changed the attachment")
				}
			} else if resp.StatusCode != http.StatusOK || f.bk.has(attID) {
				t.Fatalf("completed body was not processed: %d %s", resp.StatusCode, response)
			}
		})
	}
}
