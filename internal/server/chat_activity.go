package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/envelope"
)

// chatActivityAt returns a chat's last conversation activity: the later
// of its creation time and its newest message timestamp. Clients order
// the chat list by the same rule, so it must stay in step with the
// webapp and iOS implementations. Timestamps that are missing or not
// RFC 3339 strings are ignored, and ok is false when none remain.
func chatActivityAt(plaintext []byte) (activityAt time.Time, ok bool) {
	var chat struct {
		CreatedAt json.RawMessage   `json:"createdAt"`
		Messages  []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(plaintext, &chat); err != nil {
		return time.Time{}, false
	}
	consider := func(raw json.RawMessage) bool {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return false
		}
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return false
		}
		if parsed.After(activityAt) {
			activityAt = parsed
		}
		return true
	}
	consider(chat.CreatedAt)
	for _, rawMessage := range chat.Messages {
		var message struct {
			Timestamp json.RawMessage `json:"timestamp"`
			CreatedAt json.RawMessage `json:"createdAt"`
		}
		if json.Unmarshal(rawMessage, &message) == nil {
			if !consider(message.CreatedAt) {
				consider(message.Timestamp)
			}
		}
	}
	return activityAt, !activityAt.IsZero()
}

// backfillChatActivity records the activity time of a chat whose row
// was written before the controlplane tracked it, using the plaintext
// this pull just decrypted. etag is the row's current etag, which
// differs from the one read when the pull rewrapped the row. It is
// best-effort: the controlplane only applies it while the row is still
// at etag and has no value, and a failure leaves the row sorting by its
// write time until the next pull.
func backfillChatActivity(ctx context.Context, deps Deps, sess Session, scope envelope.Scope, id string, blob *controlplane.GetBlobResponse, etag string, plaintext []byte) {
	if scope != envelope.ScopeChat || blob.ActivityAt != nil {
		return
	}
	activityAt, ok := chatActivityAt(plaintext)
	if !ok {
		return
	}
	_ = deps.Controlplane.BackfillChatActivity(ctx, sess.RawJWT, sess.Claims.Subject, id, etag, activityAt)
}
