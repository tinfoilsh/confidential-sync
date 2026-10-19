package server

import (
	"encoding/json"
	"time"
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
	consider := func(raw json.RawMessage) {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return
		}
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return
		}
		if parsed.After(activityAt) {
			activityAt = parsed
		}
	}
	consider(chat.CreatedAt)
	for _, rawMessage := range chat.Messages {
		var message struct {
			Timestamp json.RawMessage `json:"timestamp"`
		}
		if json.Unmarshal(rawMessage, &message) == nil {
			consider(message.Timestamp)
		}
	}
	return activityAt, !activityAt.IsZero()
}
