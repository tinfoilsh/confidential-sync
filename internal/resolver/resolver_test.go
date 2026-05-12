package resolver

import (
	"encoding/json"
	"testing"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestForUnknownScope(t *testing.T) {
	if _, err := For("bogus"); err == nil {
		t.Fatal("expected error")
	}
}

// -------- chat --------

func TestChatRejectsDifferentID(t *testing.T) {
	r, _ := For("chat")
	l := mustJSON(t, map[string]any{"id": "a", "messages": []any{}})
	rem := mustJSON(t, map[string]any{"id": "b", "messages": []any{}})
	if _, err := r.Merge(l, rem); !IsConflict(err) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestChatAppendOnlyMerge(t *testing.T) {
	r, _ := For("chat")
	base := []any{
		map[string]any{"role": "user", "content": "hi", "timestamp": "2026-05-01T00:00:00Z"},
		map[string]any{"role": "assistant", "content": "hello", "timestamp": "2026-05-01T00:00:01Z"},
	}
	localExtra := append([]any{}, base...)
	localExtra = append(localExtra, map[string]any{"role": "user", "content": "L", "timestamp": "2026-05-01T00:00:02Z"})

	remoteExtra := append([]any{}, base...)
	remoteExtra = append(remoteExtra, map[string]any{"role": "user", "content": "R", "timestamp": "2026-05-01T00:00:03Z"})

	l := mustJSON(t, map[string]any{"id": "c", "messages": localExtra, "title": "L title"})
	rem := mustJSON(t, map[string]any{"id": "c", "messages": remoteExtra, "title": "R title"})
	res, err := r.Merge(l, rem)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatalf("expected changed=true")
	}
	var out map[string]any
	if err := json.Unmarshal(res.Plaintext, &out); err != nil {
		t.Fatal(err)
	}
	msgs, _ := out["messages"].([]any)
	if len(msgs) != 4 {
		t.Fatalf("messages: %d, want 4", len(msgs))
	}
	first := msgs[0].(map[string]any)
	last := msgs[3].(map[string]any)
	if first["timestamp"] != "2026-05-01T00:00:00Z" {
		t.Fatalf("expected timestamp ordering, got first=%v", first["timestamp"])
	}
	if last["timestamp"] != "2026-05-01T00:00:03Z" {
		t.Fatalf("expected timestamp ordering, got last=%v", last["timestamp"])
	}
	if out["title"] != "R title" {
		t.Fatalf("title: %v", out["title"])
	}
}

func TestChatMergeDeterministicByTimestamp(t *testing.T) {
	r, _ := For("chat")
	// Two devices each compose one message offline; ordering must follow
	// timestamps, not which side is "local".
	local := []any{
		map[string]any{"role": "user", "content": "A", "timestamp": "2026-05-01T00:00:02Z"},
	}
	remote := []any{
		map[string]any{"role": "user", "content": "B", "timestamp": "2026-05-01T00:00:01Z"},
	}
	l := mustJSON(t, map[string]any{"id": "c", "messages": local})
	rem := mustJSON(t, map[string]any{"id": "c", "messages": remote})
	res, err := r.Merge(l, rem)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(res.Plaintext, &out)
	msgs := out["messages"].([]any)
	if msgs[0].(map[string]any)["content"] != "B" {
		t.Fatalf("expected B first, got %v", msgs[0])
	}
}

func TestChatMergeDedupesIdenticalMessages(t *testing.T) {
	r, _ := For("chat")
	same := map[string]any{"role": "user", "content": "hi", "timestamp": "2026-05-01T00:00:00Z"}
	l := mustJSON(t, map[string]any{"id": "c", "messages": []any{same}})
	rem := mustJSON(t, map[string]any{"id": "c", "messages": []any{same}})
	res, err := r.Merge(l, rem)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(res.Plaintext, &out)
	if len(out["messages"].([]any)) != 1 {
		t.Fatalf("expected dedup")
	}
}

func TestChatMergeUsesExplicitIDWhenPresent(t *testing.T) {
	r, _ := For("chat")
	// Same message id with diverging non-attachment field → conflict.
	l := mustJSON(t, map[string]any{"id": "c", "messages": []any{
		map[string]any{"id": "msg-1", "role": "user", "content": "A", "timestamp": "t"},
	}})
	rem := mustJSON(t, map[string]any{"id": "c", "messages": []any{
		map[string]any{"id": "msg-1", "role": "user", "content": "B", "timestamp": "t"},
	}})
	if _, err := r.Merge(l, rem); !IsConflict(err) {
		t.Fatalf("expected conflict on same explicit id with different content")
	}
}

func TestChatMergesAttachmentsByID(t *testing.T) {
	r, _ := For("chat")
	ts := "2026-05-01T00:00:00Z"
	l := mustJSON(t, map[string]any{"id": "c", "messages": []any{
		map[string]any{
			"role": "user", "content": "msg", "timestamp": ts,
			"attachments": []any{
				map[string]any{"id": "att-1", "fileName": "a.png", "type": "image"},
			},
		},
	}})
	rem := mustJSON(t, map[string]any{"id": "c", "messages": []any{
		map[string]any{
			"role": "user", "content": "msg", "timestamp": ts,
			"attachments": []any{
				map[string]any{"id": "att-1", "fileName": "a.png", "type": "image"},
				map[string]any{"id": "att-2", "fileName": "b.png", "type": "image"},
			},
		},
	}})
	res, err := r.Merge(l, rem)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(res.Plaintext, &out)
	msgs := out["messages"].([]any)
	atts := msgs[0].(map[string]any)["attachments"].([]any)
	if len(atts) != 2 {
		t.Fatalf("attachments: %d, want 2", len(atts))
	}
}

func TestChatAttachmentSameIDDifferentContentConflict(t *testing.T) {
	r, _ := For("chat")
	ts := "2026-05-01T00:00:00Z"
	l := mustJSON(t, map[string]any{"id": "c", "messages": []any{
		map[string]any{
			"role": "user", "content": "msg", "timestamp": ts,
			"attachments": []any{
				map[string]any{"id": "att-1", "fileName": "a.png"},
			},
		},
	}})
	rem := mustJSON(t, map[string]any{"id": "c", "messages": []any{
		map[string]any{
			"role": "user", "content": "msg", "timestamp": ts,
			"attachments": []any{
				map[string]any{"id": "att-1", "fileName": "b.png"},
			},
		},
	}})
	if _, err := r.Merge(l, rem); !IsConflict(err) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestChatNoChangeIsNotChanged(t *testing.T) {
	r, _ := For("chat")
	c := mustJSON(t, map[string]any{
		"id":       "c",
		"messages": []any{},
		"title":    "t",
	})
	res, err := r.Merge(c, c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatalf("expected unchanged")
	}
}

// -------- profile --------

func TestProfileNonOverlappingFields(t *testing.T) {
	r, _ := For("profile")
	l := mustJSON(t, map[string]any{"display_name": "Sacha"})
	rem := mustJSON(t, map[string]any{"locale": "en-US"})
	res, err := r.Merge(l, rem)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(res.Plaintext, &out)
	if out["display_name"] != "Sacha" || out["locale"] != "en-US" {
		t.Fatalf("merged: %+v", out)
	}
}

func TestProfileSameFieldConflict(t *testing.T) {
	r, _ := For("profile")
	l := mustJSON(t, map[string]any{"display_name": "A"})
	rem := mustJSON(t, map[string]any{"display_name": "B"})
	if _, err := r.Merge(l, rem); !IsConflict(err) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestProfileLastWriterWinsAllowlist(t *testing.T) {
	r, _ := For("profile")
	l := mustJSON(t, map[string]any{"theme": "light"})
	rem := mustJSON(t, map[string]any{"theme": "dark"})
	res, err := r.Merge(l, rem)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(res.Plaintext, &out)
	if out["theme"] != "dark" {
		t.Fatalf("theme: %v", out["theme"])
	}
}

func TestProfileNestedMergeable(t *testing.T) {
	r, _ := For("profile")
	l := mustJSON(t, map[string]any{
		"notifications": map[string]any{"email": true},
	})
	rem := mustJSON(t, map[string]any{
		"notifications": map[string]any{"push": false},
	})
	res, err := r.Merge(l, rem)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(res.Plaintext, &out)
	n, _ := out["notifications"].(map[string]any)
	if n == nil || n["email"] != true || n["push"] != false {
		t.Fatalf("nested merge wrong: %+v", out)
	}
}

func TestProfileNestedConflict(t *testing.T) {
	r, _ := For("profile")
	l := mustJSON(t, map[string]any{
		"notifications": map[string]any{"email": true},
	})
	rem := mustJSON(t, map[string]any{
		"notifications": map[string]any{"email": false},
	})
	if _, err := r.Merge(l, rem); !IsConflict(err) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if !contains(ConflictReason(&Conflict{Reason: "profile_field_conflict:notifications/email"}), "notifications/email") {
		t.Fatalf("expected nested path in reason")
	}
}

// -------- project --------

func TestProjectMergesNonOverlapping(t *testing.T) {
	r, _ := For("project")
	l := mustJSON(t, map[string]any{"id": "p", "name": "Demo", "instructions": "old"})
	rem := mustJSON(t, map[string]any{"id": "p", "name": "Demo", "color": "blue"})
	res, err := r.Merge(l, rem)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(res.Plaintext, &out)
	if out["instructions"] != "old" || out["color"] != "blue" {
		t.Fatalf("merge: %+v", out)
	}
}

func TestProjectNameConflict(t *testing.T) {
	r, _ := For("project")
	l := mustJSON(t, map[string]any{"id": "p", "name": "A"})
	rem := mustJSON(t, map[string]any{"id": "p", "name": "B"})
	if _, err := r.Merge(l, rem); !IsConflict(err) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestProjectDocumentListUnion(t *testing.T) {
	r, _ := For("project")
	l := mustJSON(t, map[string]any{"id": "p", "document_ids": []any{"d1", "d2"}})
	rem := mustJSON(t, map[string]any{"id": "p", "document_ids": []any{"d2", "d3"}})
	res, err := r.Merge(l, rem)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(res.Plaintext, &out)
	docs, _ := out["document_ids"].([]any)
	if len(docs) != 3 {
		t.Fatalf("docs: %+v", docs)
	}
}

// -------- project document --------

func TestProjectDocumentEqualNoChange(t *testing.T) {
	r, _ := For("project_document")
	b := []byte(`{"x":1}`)
	res, err := r.Merge(b, b)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatalf("expected unchanged")
	}
}

func TestProjectDocumentDifferentConflicts(t *testing.T) {
	r, _ := For("project_document")
	a := []byte(`{"x":1}`)
	b := []byte(`{"x":2}`)
	if _, err := r.Merge(a, b); !IsConflict(err) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
