package importer

import (
	"encoding/json"
	"testing"
	"time"
)

// FuzzParseClaude drives the Claude parser with structurally valid JSON
// whose field types and shapes are mutated, so any panic on an
// unexpected export layout surfaces as a test failure rather than a
// worker_failed job in production.
func FuzzParseClaude(f *testing.F) {
	seeds := []string{
		`[]`,
		`[{}]`,
		`[{"uuid":"a","name":"n","created_at":"2024-01-01T00:00:00Z","chat_messages":[]}]`,
		`[{"uuid":"a","chat_messages":[{"sender":"human","text":"hi"}]}]`,
		`[{"uuid":"a","chat_messages":[{"sender":"assistant","text":"","content":[{"type":"text","text":"in content only"}]}]}]`,
		`[{"uuid":"a","chat_messages":[{"sender":"assistant","text":"x","content":[{"type":"thinking","thinking":"t","start_timestamp":"2024-01-01T00:00:00Z"}]}]}]`,
		`[{"uuid":"a","chat_messages":[{"sender":"assistant","text":"x","content":[{"type":"thinking","thinking":"t","start_timestamp":"bad","stop_timestamp":""}]}]}]`,
		`[{"uuid":"a","chat_messages":[{"sender":"human","text":"x","attachments":[{"file_name":"f","file_size":1,"extracted_content":"c"}]}]}]`,
		`[{"uuid":"a","chat_messages":[{"sender":"human","text":"x","attachments":[{"file_name":"f","extracted_content":""}]}]}]`,
		`[{"uuid":"a","chat_messages":[{"sender":"human","text":"x","files":[{"file_name":"img.png","file_uuid":"u1"}],"files_v2":[{"file_name":"img.png","file_uuid":"u1"}]}]}]`,
		`[{"uuid":"a","chat_messages":[{"sender":"human","text":"x","files":[{"file_name":"","file_uuid":""}]}]}]`,
		`[{"uuid":"a","chat_messages":[{"sender":"human","text":"x","files":[{}]}]}]`,
		`[{"uuid":"a","chat_messages":[{"sender":"system","text":"x"}]}]`,
		`[{"uuid":"a","chat_messages":[{"sender":"human","text":"x","content":null,"attachments":null,"files":null}]}]`,
		`[{"uuid":"","name":"","created_at":"","chat_messages":[{"sender":"human","text":"x","created_at":"not-a-time"}]}]`,
		`[{"uuid":"a","chat_messages":[{"sender":"human","text":"x","attachments":[{"file_size":-1,"extracted_content":"c"}]}]}]`,
		`[{"uuid":"a","chat_messages":[{"sender":"human","text":"x","files":[{"file_name":"../../etc/passwd","file_uuid":"u"}]}]}]`,
		`[{"uuid":"a","chat_messages":[{"sender":"human","text":"x","files":[{"file_name":"img.png","file_uuid":"u"}]}]},{"uuid":"a","chat_messages":[{"sender":"human","text":"dup"}]}]`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	idx := NewIndex([]string{"img.png", "dir/u1-photo.jpg", "u-file.png"})
	opts := Options{
		Index: idx,
		GenerateID: func(stableKey string, createdAt time.Time) string {
			return "id:" + stableKey + ":" + createdAt.UTC().Format(time.RFC3339)
		},
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if !json.Valid(data) {
			return
		}
		emitted := 0
		_, _ = parseClaude(data, opts, func(c *Chat) error {
			emitted++
			if c == nil {
				t.Fatal("emitted nil chat")
			}
			if c.ID == "" {
				t.Fatal("emitted chat with empty id")
			}
			if len(c.Messages) == 0 {
				t.Fatal("emitted chat with no messages")
			}
			for _, m := range c.Messages {
				if m.Role != "user" && m.Role != "assistant" {
					t.Fatalf("emitted message with invalid role %q", m.Role)
				}
			}
			// Exercise the same marshal the sealer performs.
			if _, err := json.Marshal(c); err != nil {
				t.Fatalf("emitted chat does not marshal: %v", err)
			}
			return nil
		})
	})
}
