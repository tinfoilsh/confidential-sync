package importer

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func collect(t *testing.T, source Source, data []byte, idx *Index) ([]*Chat, Result) {
	t.Helper()
	opts := Options{
		Index: idx,
		GenerateID: func(stableKey string, createdAt time.Time) string {
			return "id:" + stableKey
		},
	}
	var chats []*Chat
	res, err := ParseEach(source, data, opts, func(c *Chat) error {
		chats = append(chats, c)
		return nil
	})
	if err != nil {
		t.Fatalf("ParseEach(%s): %v", source, err)
	}
	return chats, res
}

func TestParseChatGPTTraversalAndThoughts(t *testing.T) {
	data := []byte(`[
      {
        "id": "conv-1",
        "title": "Hello",
        "create_time": 1700000000,
        "mapping": {
          "root": {"id":"root","parent":"","children":["u1"]},
          "u1": {"id":"u1","parent":"root","children":["t1"],"message":{"author":{"role":"user"},"content":{"content_type":"text","parts":["Hi there"]},"create_time":1700000001}},
          "t1": {"id":"t1","parent":"u1","children":["a1"],"message":{"author":{"role":"assistant"},"content":{"content_type":"thoughts","thoughts":[{"content":"let me think"}]}}},
          "a1": {"id":"a1","parent":"t1","children":[],"message":{"author":{"role":"assistant"},"content":{"content_type":"text","parts":["Hello!"]},"create_time":1700000005}}
        }
      }
    ]`)

	chats, res := collect(t, SourceChatGPT, data, nil)
	if len(chats) != 1 {
		t.Fatalf("expected 1 chat, got %d", len(chats))
	}
	chat := chats[0]
	if chat.ID != "id:conv-1" {
		t.Fatalf("unexpected id %q", chat.ID)
	}
	if chat.Title != "Hello" {
		t.Fatalf("unexpected title %q", chat.Title)
	}
	if len(chat.Messages) != 2 {
		t.Fatalf("expected 2 rendered messages, got %d", len(chat.Messages))
	}
	if chat.Messages[0].Role != "user" || chat.Messages[0].Content != "Hi there" {
		t.Fatalf("unexpected first message: %+v", chat.Messages[0])
	}
	assistant := chat.Messages[1]
	if assistant.Role != "assistant" || assistant.Content != "Hello!" {
		t.Fatalf("unexpected assistant message: %+v", assistant)
	}
	if assistant.Thoughts != "let me think" {
		t.Fatalf("expected thoughts to be threaded, got %q", assistant.Thoughts)
	}
	if res.Conversations != 1 || res.Messages != 2 {
		t.Fatalf("unexpected result counts: %+v", res)
	}
}

func TestParseChatGPTUsesCurrentNodePath(t *testing.T) {
	data := []byte(`[
      {
        "id": "conv-branch",
        "title": "Branch",
        "create_time": 1700000000,
        "current_node": "a2",
        "mapping": {
          "u1": {"id":"u1","parent":"client-created-root","children":["a1","a2"],"message":{"author":{"role":"user"},"content":{"content_type":"text","parts":["Hi"]},"create_time":1700000001}},
          "a1": {"id":"a1","parent":"u1","children":[],"message":{"author":{"role":"assistant"},"content":{"content_type":"text","parts":["old reply"]},"create_time":1700000002}},
          "a2": {"id":"a2","parent":"u1","children":[],"message":{"author":{"role":"assistant"},"content":{"content_type":"text","parts":["current reply"]},"create_time":1700000003}}
        }
      }
    ]`)

	chats, _ := collect(t, SourceChatGPT, data, nil)
	if len(chats) != 1 {
		t.Fatalf("expected 1 chat, got %d", len(chats))
	}
	if len(chats[0].Messages) != 2 {
		t.Fatalf("expected active path to render 2 messages, got %d", len(chats[0].Messages))
	}
	if got := chats[0].Messages[1].Content; got != "current reply" {
		t.Fatalf("expected current reply, got %q", got)
	}
}

func TestParseChatGPTFallbackStopsOnCycles(t *testing.T) {
	data := []byte(`[
      {
        "id": "conv-cycle",
        "title": "Cycle",
        "create_time": 1700000000,
        "mapping": {
          "u1": {"id":"u1","parent":"","children":["a1"],"message":{"author":{"role":"user"},"content":{"content_type":"text","parts":["Hi"]},"create_time":1700000001}},
          "a1": {"id":"a1","parent":"u1","children":["u1"],"message":{"author":{"role":"assistant"},"content":{"content_type":"text","parts":["Hello"]},"create_time":1700000002}}
        }
      }
    ]`)

	chats, _ := collect(t, SourceChatGPT, data, nil)
	if len(chats) != 1 {
		t.Fatalf("expected 1 chat, got %d", len(chats))
	}
	if len(chats[0].Messages) != 2 {
		t.Fatalf("expected cycle-safe branch to render 2 messages, got %d", len(chats[0].Messages))
	}
}

func TestParseChatGPTAttachments(t *testing.T) {
	data := []byte(`[
      {
        "id": "conv-att",
        "title": "Pics",
        "create_time": 1700000000,
        "mapping": {
          "u1": {"id":"u1","parent":"","children":[],"message":{
            "author":{"role":"user"},
            "content":{"content_type":"multimodal_text","parts":["look",{"content_type":"image_asset_pointer","asset_pointer":"file-service://file-ABC"}]},
            "metadata":{"attachments":[{"id":"file-DEF","name":"notes.pdf","mime_type":"application/pdf"}]}
          }}
        }
      }
    ]`)

	idx := NewIndex([]string{"file-ABC-1234.png", "dalle-generations/file-XYZ.webp"})
	chats, _ := collect(t, SourceChatGPT, data, idx)
	if len(chats) != 1 {
		t.Fatalf("expected 1 chat, got %d", len(chats))
	}
	atts := chats[0].Messages[0].Attachments
	if len(atts) != 2 {
		t.Fatalf("expected 2 attachments, got %d: %+v", len(atts), atts)
	}
	var doc, img *Attachment
	for i := range atts {
		switch atts[i].Type {
		case AttachmentDocument:
			doc = &atts[i]
		case AttachmentImage:
			img = &atts[i]
		}
	}
	if doc == nil || doc.FileName != "notes.pdf" || doc.BinaryRef != "" {
		t.Fatalf("unexpected document attachment: %+v", doc)
	}
	if img == nil || img.BinaryRef != "file-ABC-1234.png" || img.MimeType != "image/png" {
		t.Fatalf("unexpected image attachment: %+v", img)
	}
}

func TestParseChatGPTAttachmentOnlyMessage(t *testing.T) {
	data := []byte(`[
      {
        "id": "conv-attachment-only",
        "title": "Attachment only",
        "create_time": 1700000000,
        "mapping": {
          "u1": {"id":"u1","parent":"","children":[],"message":{
            "author":{"role":"user"},
            "content":{"content_type":"multimodal_text"},
            "metadata":{"attachments":[{"id":"file-ABC","name":"pic.png","mime_type":"image/png"}]}
          }}
        }
      }
    ]`)

	idx := NewIndex([]string{"file-ABC-1234.png"})
	chats, _ := collect(t, SourceChatGPT, data, idx)
	if len(chats) != 1 {
		t.Fatalf("expected 1 chat, got %d", len(chats))
	}
	atts := chats[0].Messages[0].Attachments
	if len(atts) != 1 || atts[0].BinaryRef != "file-ABC-1234.png" {
		t.Fatalf("unexpected attachments: %+v", atts)
	}
}

func TestIndexExactDoesNotFallBackToBasename(t *testing.T) {
	idx := NewIndex([]string{"safe/pic.png"})
	if got, ok := idx.Exact("other/pic.png"); ok {
		t.Fatalf("Exact returned basename fallback %q", got)
	}
	if got, ok := idx.Basename("other/pic.png"); !ok || got != "safe/pic.png" {
		t.Fatalf("Basename = (%q,%v), want safe/pic.png,true", got, ok)
	}
}

func TestParseClaudeThinkingAndDocuments(t *testing.T) {
	data := []byte(`[
      {
        "uuid": "claude-1",
        "name": "Doc chat",
        "created_at": "2023-11-14T22:13:20Z",
        "chat_messages": [
          {"uuid":"m1","sender":"human","text":"read this","created_at":"2023-11-14T22:13:21Z","attachments":[{"file_name":"spec.txt","extracted_content":"the contents","file_size":12}]},
          {"uuid":"m2","sender":"assistant","text":"done","created_at":"2023-11-14T22:13:30Z","content":[{"type":"thinking","thinking":"hmm","start_timestamp":"2023-11-14T22:13:22Z","stop_timestamp":"2023-11-14T22:13:27Z"}]}
        ]
      }
    ]`)

	chats, _ := collect(t, SourceClaude, data, nil)
	if len(chats) != 1 {
		t.Fatalf("expected 1 chat, got %d", len(chats))
	}
	chat := chats[0]
	if chat.ID != "id:claude-1" {
		t.Fatalf("unexpected id %q", chat.ID)
	}
	first := chat.Messages[0]
	if first.Role != "user" || len(first.Attachments) != 1 {
		t.Fatalf("unexpected first message: %+v", first)
	}
	if first.Attachments[0].Type != AttachmentDocument || first.Attachments[0].TextContent != "the contents" {
		t.Fatalf("unexpected document attachment: %+v", first.Attachments[0])
	}
	second := chat.Messages[1]
	if second.Thoughts != "hmm" {
		t.Fatalf("expected thinking content, got %q", second.Thoughts)
	}
	if second.ThinkingDuration != 5 {
		t.Fatalf("expected 5s thinking duration, got %d", second.ThinkingDuration)
	}
}

func TestParseClaudeSkipsUnknownSenders(t *testing.T) {
	data := []byte(`[
      {
        "uuid": "claude-unknown",
        "name": "Unknown sender",
        "created_at": "2023-11-14T22:13:20Z",
        "chat_messages": [
          {"uuid":"m1","sender":"human","text":"hello","created_at":"2023-11-14T22:13:21Z"},
          {"uuid":"m2","sender":"system","text":"internal note","created_at":"2023-11-14T22:13:22Z"}
        ]
      }
    ]`)

	chats, _ := collect(t, SourceClaude, data, nil)
	if len(chats) != 1 {
		t.Fatalf("expected 1 chat, got %d", len(chats))
	}
	if len(chats[0].Messages) != 1 {
		t.Fatalf("expected unknown sender to be skipped, got %d messages", len(chats[0].Messages))
	}
	if got := chats[0].Messages[0].Role; got != "user" {
		t.Fatalf("expected human message role user, got %q", got)
	}
}

func TestParseTinfoilRoundTripShape(t *testing.T) {
	data := []byte(`[
      {
        "uuid": "tf-1",
        "name": "Exported",
        "created_at": "2023-11-14T22:13:20.000Z",
        "chat_messages": [
          {"sender":"human","text":"see image","created_at":"2023-11-14T22:13:21.000Z","attachments":[
            {"id":"att-1","type":"image","fileName":"pic.png","mimeType":"image/png","fileSize":99,"exportPath":"attachments/att-1/pic.png"},
            {"id":"att-2","type":"document","fileName":"a.txt","textContent":"inline text"}
          ]}
        ]
      }
    ]`)

	idx := NewIndex([]string{"attachments/att-1/pic.png"})
	chats, _ := collect(t, SourceTinfoil, data, idx)
	if len(chats) != 1 {
		t.Fatalf("expected 1 chat, got %d", len(chats))
	}
	atts := chats[0].Messages[0].Attachments
	if len(atts) != 2 {
		t.Fatalf("expected 2 attachments, got %d", len(atts))
	}
	if atts[0].Type != AttachmentImage || atts[0].BinaryRef != "attachments/att-1/pic.png" {
		t.Fatalf("unexpected image attachment: %+v", atts[0])
	}
	if atts[1].Type != AttachmentDocument || atts[1].TextContent != "inline text" {
		t.Fatalf("unexpected document attachment: %+v", atts[1])
	}
}

// TestSealedJSONShape asserts the emitted chat serializes into the
// camelCase shape the webapp StoredChat reader expects, with ISO-8601
// timestamps and no parser-only fields leaking in.
func TestSealedJSONShape(t *testing.T) {
	chat := &Chat{
		ID:        "abc",
		Title:     "T",
		CreatedAt: jsTime{time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)},
		StableKey: "should-not-serialize",
		Messages: []Message{
			{
				Role:      "user",
				Content:   "hi",
				Timestamp: jsTime{time.Date(2023, 11, 14, 22, 13, 21, 0, time.UTC)},
				Attachments: []Attachment{
					{ID: "i1", Type: AttachmentImage, FileName: "p.png", MimeType: "image/png", BinaryRef: "secret/path"},
				},
			},
		},
	}

	raw, err := json.Marshal(chat)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)

	for _, want := range []string{
		`"id":"abc"`,
		`"createdAt":"2023-11-14T22:13:20.000Z"`,
		`"timestamp":"2023-11-14T22:13:21.000Z"`,
		`"isLocalOnly":false`,
		`"fileName":"p.png"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("sealed JSON missing %s: %s", want, s)
		}
	}
	for _, unwanted := range []string{"StableKey", "should-not-serialize", "BinaryRef", "secret/path"} {
		if strings.Contains(s, unwanted) {
			t.Fatalf("sealed JSON leaked %s: %s", unwanted, s)
		}
	}

	// Verify it parses back into a generic StoredChat-shaped object.
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if back["isLocalOnly"] != false {
		t.Fatalf("expected isLocalOnly false, got %v", back["isLocalOnly"])
	}
}

func TestParseEachUnsupportedSource(t *testing.T) {
	_, err := ParseEach(Source("bogus"), []byte("[]"), Options{}, func(*Chat) error { return nil })
	if err == nil {
		t.Fatal("expected error for unsupported source")
	}
}

func TestParseEachRejectsNilEmit(t *testing.T) {
	_, err := ParseEach(SourceChatGPT, []byte("[]"), Options{}, nil)
	if err == nil {
		t.Fatal("expected error for nil emit")
	}
}
