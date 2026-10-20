package server

import (
	"testing"
	"time"
)

func TestChatActivityAt(t *testing.T) {
	cases := []struct {
		name      string
		plaintext string
		want      string
	}{
		{
			name:      "harness messages and existing messages share activity ordering",
			plaintext: `{"createdAt":"2025-01-01T00:00:00Z","updatedAt":"2030-01-01T00:00:00Z","messages":[{"createdAt":"2026-03-01T00:00:00Z","timestamp":"2031-01-01T00:00:00Z"},{"timestamp":"2026-02-01T00:00:00Z"}]}`,
			want:      "2026-03-01T00:00:00Z",
		},
		{
			name:      "newest message wins over creation",
			plaintext: `{"createdAt":"2025-01-01T00:00:00.000Z","messages":[{"timestamp":"2025-03-01T10:00:00.000Z"},{"timestamp":"2025-02-01T10:00:00.000Z"}]}`,
			want:      "2025-03-01T10:00:00Z",
		},
		{
			name:      "creation wins when it is later, as for a fork",
			plaintext: `{"createdAt":"2026-01-01T00:00:00Z","messages":[{"timestamp":"2025-03-01T10:00:00Z"}]}`,
			want:      "2026-01-01T00:00:00Z",
		},
		{
			name:      "offsets and fractional seconds compare as instants",
			plaintext: `{"createdAt":"2025-01-01T00:00:00Z","messages":[{"timestamp":"2025-03-01T12:00:00.5+02:00"},{"timestamp":"2025-03-01T10:00:00.25Z"}]}`,
			want:      "2025-03-01T10:00:00.5Z",
		},
		{
			name:      "unparseable and non-string timestamps are ignored",
			plaintext: `{"createdAt":null,"messages":[{"timestamp":1700000000000},"not a message",{"timestamp":"yesterday"},{"timestamp":"2025-04-01T00:00:00Z"}]}`,
			want:      "2025-04-01T00:00:00Z",
		},
		{name: "no usable timestamp", plaintext: `{"createdAt":"soon","messages":[]}`},
		{name: "not a chat object", plaintext: `["2025-04-01T00:00:00Z"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := chatActivityAt([]byte(tc.plaintext))
			if tc.want == "" {
				if ok {
					t.Fatalf("got %s, want no activity time", got)
				}
				return
			}
			want, err := time.Parse(time.RFC3339Nano, tc.want)
			if err != nil {
				t.Fatal(err)
			}
			if !ok || !got.Equal(want) {
				t.Fatalf("got %s (ok=%v), want %s", got, ok, want)
			}
		})
	}
}
