package server

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/importer"
)

const retryTestArchive = `[{"uuid":"conv-1","name":"Hello","created_at":"2024-01-01T00:00:00Z","chat_messages":[{"sender":"human","text":"hi there","created_at":"2024-01-01T00:00:00Z"}]}]`

// stubImportSleep records requested backoff delays without waiting.
func stubImportSleep(t *testing.T) *[]time.Duration {
	t.Helper()
	var delays []time.Duration
	previous := importSleep
	importSleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		delays = append(delays, d)
		return nil
	}
	t.Cleanup(func() { importSleep = previous })
	return &delays
}

func TestRetryTransientImportCallBacksOffThenSucceeds(t *testing.T) {
	delays := stubImportSleep(t)
	attempts := 0
	err := retryTransientImportCall(context.Background(), func() error {
		attempts++
		if attempts < importRetryMaxAttempts {
			return &controlplane.Error{StatusCode: http.StatusServiceUnavailable}
		}
		return nil
	})
	if err != nil || attempts != importRetryMaxAttempts {
		t.Fatalf("err=%v attempts=%d, want nil/%d", err, attempts, importRetryMaxAttempts)
	}
	want := []time.Duration{importRetryBaseDelay, importRetryBaseDelay * 2}
	if len(*delays) != len(want) || (*delays)[0] != want[0] || (*delays)[1] != want[1] {
		t.Fatalf("delays=%v, want %v", *delays, want)
	}
}

func TestRetryTransientImportCallGivesUpAfterMaxAttempts(t *testing.T) {
	stubImportSleep(t)
	attempts := 0
	cause := &controlplane.Error{StatusCode: http.StatusTooManyRequests}
	err := retryTransientImportCall(context.Background(), func() error {
		attempts++
		return cause
	})
	if !errors.Is(err, cause) || attempts != importRetryMaxAttempts {
		t.Fatalf("err=%v attempts=%d, want cause/%d", err, attempts, importRetryMaxAttempts)
	}
}

func TestRetryTransientImportCallDoesNotRetryDefinitiveErrors(t *testing.T) {
	delays := stubImportSleep(t)
	for name, cause := range map[string]error{
		"stale key":   &AppError{Code: CodeStaleKey},
		"conflict":    &AppError{Code: CodeSyncConflict},
		"bad request": &controlplane.Error{StatusCode: http.StatusBadRequest},
		"forbidden":   &controlplane.Error{StatusCode: http.StatusForbidden},
		"unknown":     errors.New("something definitive"),
	} {
		t.Run(name, func(t *testing.T) {
			attempts := 0
			err := retryTransientImportCall(context.Background(), func() error {
				attempts++
				return cause
			})
			if !errors.Is(err, cause) || attempts != 1 {
				t.Fatalf("err=%v attempts=%d, want cause/1", err, attempts)
			}
		})
	}
	if len(*delays) != 0 {
		t.Fatalf("definitive errors must not back off, got %v", *delays)
	}
}

func TestRetryTransientImportCallStopsOnJobDeadline(t *testing.T) {
	stubImportSleep(t)
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	err := retryTransientImportCall(ctx, func() error {
		attempts++
		cancel()
		return &controlplane.Error{StatusCode: http.StatusServiceUnavailable}
	})
	if err == nil || attempts != 1 {
		t.Fatalf("err=%v attempts=%d, want error after one attempt once the job is canceled", err, attempts)
	}
}

func TestImportJobRecoversFromTransientProbeFailure(t *testing.T) {
	stubImportSleep(t)
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	notified := captureImportNotifications(t, f)

	createdAt := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	priorID := priorDeterministicChatID(importer.SourceTinfoil, "conv-1", createdAt)
	f.cp.getBlobFailures["chat/"+priorID] = []int{http.StatusServiceUnavailable, http.StatusGatewayTimeout}

	job := stageArchive(t, f, "tinfoil", []byte(retryTestArchive))
	snap := runCoordinatorJob(t, f, NewImportCoordinator(), job)

	if snap.Status != ImportJobCompleted || snap.Imported != 1 || snap.Failed != 0 {
		t.Fatalf("status=%s imported=%d failed=%d errors=%v, want completed/1/0", snap.Status, snap.Imported, snap.Failed, snap.Errors)
	}
	if len(snap.Warnings) != 0 {
		t.Fatalf("a probe that recovers within the retry budget must not warn: %v", snap.Warnings)
	}
	if body := notified.single(t); body["status"] != "completed" {
		t.Fatalf("notification=%v, want completed", body)
	}
}

func TestImportJobContinuesWhenProbeStaysUnavailable(t *testing.T) {
	stubImportSleep(t)
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	notified := captureImportNotifications(t, f)

	createdAt := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	priorID := priorDeterministicChatID(importer.SourceTinfoil, "conv-1", createdAt)
	failures := make([]int, importRetryMaxAttempts)
	for i := range failures {
		failures[i] = http.StatusServiceUnavailable
	}
	f.cp.getBlobFailures["chat/"+priorID] = failures

	job := stageArchive(t, f, "tinfoil", []byte(retryTestArchive))
	snap := runCoordinatorJob(t, f, NewImportCoordinator(), job)

	if snap.Status != ImportJobCompleted || snap.Imported != 1 || snap.Failed != 0 {
		t.Fatalf("status=%s imported=%d failed=%d errors=%v, want completed/1/0", snap.Status, snap.Imported, snap.Failed, snap.Errors)
	}
	if len(snap.Warnings) != 1 {
		t.Fatalf("expected one probe warning, got %v", snap.Warnings)
	}
	if len(f.cp.blobs) != 1 {
		t.Fatalf("expected exactly one chat written, got %d", len(f.cp.blobs))
	}
	if body := notified.single(t); body["status"] != "completed" {
		t.Fatalf("notification=%v, want completed", body)
	}
}

func TestImportJobProbeFallbackWritesUnderCurrentID(t *testing.T) {
	stubImportSleep(t)
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID

	createdAt := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	priorID := priorDeterministicChatID(importer.SourceTinfoil, "conv-1", createdAt)
	// Seed the pre-release row under the prior id so a duplicate would
	// be observable, then make its probe permanently unavailable.
	if _, err := Push(context.Background(), f.handler.deps, importSession(f), PushRequest{
		Scope: "chat", ID: priorID, Key: f.userKeyB64,
		Plaintext: base64.StdEncoding.EncodeToString([]byte(`{"id":"` + priorID + `"}`)), IdempotencyKey: "seed",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	failures := make([]int, importRetryMaxAttempts)
	for i := range failures {
		failures[i] = http.StatusServiceUnavailable
	}
	f.cp.getBlobFailures["chat/"+priorID] = failures

	job := stageArchive(t, f, "tinfoil", []byte(retryTestArchive))
	snap := runCoordinatorJob(t, f, NewImportCoordinator(), job)

	// The new deterministic id differs from the prior id, so the push
	// creates one new row: the fallback trades a skip for one extra
	// write of the same content under the current id family, never a
	// second copy under the same id.
	if snap.Status != ImportJobCompleted || snap.Imported != 1 {
		t.Fatalf("status=%s imported=%d errors=%v", snap.Status, snap.Imported, snap.Errors)
	}
	if len(f.cp.blobs) != 2 {
		t.Fatalf("expected seed + one import, got %d blobs", len(f.cp.blobs))
	}
}

func TestImportJobRetriesTransientPushFailure(t *testing.T) {
	stubImportSleep(t)
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	notified := captureImportNotifications(t, f)

	createdAt := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	chatID := deterministicChatID(f.userSub, importer.SourceTinfoil, "conv-1", createdAt)
	// PutBlob already absorbs one 5xx internally; inject enough that the
	// import-level retry is what carries the write to completion.
	f.cp.putBlobFailures["chat/"+chatID] = controlplane.PutBlobMaxAttempts + 1

	job := stageArchive(t, f, "tinfoil", []byte(retryTestArchive))
	snap := runCoordinatorJob(t, f, NewImportCoordinator(), job)

	if snap.Status != ImportJobCompleted || snap.Imported != 1 || snap.Failed != 0 {
		t.Fatalf("status=%s imported=%d failed=%d errors=%v, want completed/1/0", snap.Status, snap.Imported, snap.Failed, snap.Errors)
	}
	if len(f.cp.blobs) != 1 {
		t.Fatalf("expected one chat written after retry, got %d", len(f.cp.blobs))
	}
	if body := notified.single(t); body["status"] != "completed" {
		t.Fatalf("notification=%v, want completed", body)
	}
}

func TestImportJobCountsChatFailedWhenPushStaysDown(t *testing.T) {
	stubImportSleep(t)
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	notified := captureImportNotifications(t, f)

	createdAt := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	chatID := deterministicChatID(f.userSub, importer.SourceTinfoil, "conv-1", createdAt)
	f.cp.putBlobFailures["chat/"+chatID] = 100

	job := stageArchive(t, f, "tinfoil", []byte(retryTestArchive))
	snap := runCoordinatorJob(t, f, NewImportCoordinator(), job)

	if snap.Status != ImportJobCompleted || snap.Imported != 0 || snap.Failed != 1 {
		t.Fatalf("status=%s imported=%d failed=%d, want completed/0/1 (per-chat failure, not job abort)", snap.Status, snap.Imported, snap.Failed)
	}
	if len(f.cp.blobs) != 0 {
		t.Fatalf("no chat should have been written, got %d", len(f.cp.blobs))
	}
	body := notified.single(t)
	if body["status"] != "completed" || body["failedCount"] != float64(1) {
		t.Fatalf("notification=%v, want completed with failedCount=1", body)
	}
}
