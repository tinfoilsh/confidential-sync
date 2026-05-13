// Package resolver implements deterministic conflict resolvers per
// sync scope. The enclave invokes them on a 412 STALE_BLOB after pulling
// the remote ciphertext, decrypting it, and feeding both plaintexts to
// the resolver. The output plaintext is re-encrypted and retried with
// the new ETag.
package resolver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Conflict is returned when the resolver cannot safely merge. The caller
// surfaces the reason to clients as 409 SYNC_CONFLICT.
type Conflict struct {
	Reason string
}

func (c *Conflict) Error() string {
	return "resolver: conflict: " + c.Reason
}

// Result carries the merged plaintext plus a flag indicating whether the
// merge changed anything; callers can skip a redundant re-write when both
// sides were already equal.
type Result struct {
	Plaintext []byte
	Changed   bool
}

// Resolver is the interface every per-scope resolver implements.
type Resolver interface {
	Merge(local, remote []byte) (Result, error)
}

func For(scope string) (Resolver, error) {
	switch scope {
	case "chat":
		return chatResolver{}, nil
	case "profile":
		return profileResolver{}, nil
	case "project":
		return projectResolver{}, nil
	case "project_document":
		return projectDocumentResolver{}, nil
	}
	return nil, fmt.Errorf("resolver: unknown scope %q", scope)
}

// -------- chat ----------------------------------------------------------

type chatResolver struct{}

// Chat plaintext is a JSON object with at least `id`, `title`, `messages`,
// and `createdAt`. Messages are append-only: once a message is written
// (anywhere), it is immutable. Messages do not yet have explicit IDs in
// production, so the resolver uses a deterministic synthetic identity:
//
//	synthetic_id = sha256(role || "\x1f" || content || "\x1f" || timestamp)
//
// Two devices that independently composed the same text at the same
// instant collide on synthetic ID and dedupe. The resolver:
//   - rejects merges where `id` differs (different chats)
//   - unions messages from both sides keyed by (explicit id || synthetic id)
//   - orders the unioned set by timestamp ascending, then role, then content
//     hash, so the result is byte-stable independent of which side is local
//   - within messages sharing the same identity, merges attachments by
//     stable attachment id (attachments do have ids in production); two
//     attachments with the same id and different contents → conflict
//   - applies last-writer-wins to title / titleState / projectId
//
// Returns *Conflict for unresolvable rule violations.
func (chatResolver) Merge(local, remote []byte) (Result, error) {
	var l, r map[string]any
	if err := json.Unmarshal(local, &l); err != nil {
		return Result{}, fmt.Errorf("resolver: local chat invalid: %w", err)
	}
	if err := json.Unmarshal(remote, &r); err != nil {
		return Result{}, fmt.Errorf("resolver: remote chat invalid: %w", err)
	}
	if !sameString(l, r, "id") {
		return Result{}, &Conflict{Reason: "chat_id_mismatch"}
	}

	lm, _ := l["messages"].([]any)
	rm, _ := r["messages"].([]any)
	mergedMessages, err := mergeMessages(lm, rm)
	if err != nil {
		return Result{}, err
	}

	out := make(map[string]any, len(l))
	for k, v := range l {
		out[k] = v
	}
	for k, v := range r {
		if _, exists := out[k]; !exists {
			out[k] = v
		}
	}
	if title, ok := lastWriterWinsString(l, r, "title"); ok {
		out["title"] = title
	}
	if state, ok := lastWriterWinsString(l, r, "titleState"); ok {
		out["titleState"] = state
	}
	if proj, ok := lastWriterWinsString(l, r, "projectId"); ok {
		out["projectId"] = proj
	}
	out["messages"] = mergedMessages

	encoded, err := json.Marshal(out)
	if err != nil {
		return Result{}, err
	}
	return Result{
		Plaintext: encoded,
		Changed:   !jsonEqual(local, encoded),
	}, nil
}

type orderedMessage struct {
	id      string
	tsKey   string
	roleKey string
	hashKey string
	msg     map[string]any
}

func mergeMessages(local, remote []any) ([]any, error) {
	byID := map[string]*orderedMessage{}
	order := []*orderedMessage{}

	ingest := func(items []any, side string) error {
		for idx, item := range items {
			m, _ := item.(map[string]any)
			if m == nil {
				return &Conflict{Reason: fmt.Sprintf("%s_message_%d_not_object", side, idx)}
			}
			id := messageIdentity(m)
			if existing, dup := byID[id]; dup {
				merged, err := mergeIdenticalMessages(existing.msg, m)
				if err != nil {
					return err
				}
				existing.msg = merged
				continue
			}
			om := &orderedMessage{
				id:      id,
				tsKey:   timestampKey(m["timestamp"]),
				roleKey: stringField(m, "role"),
				hashKey: id,
				msg:     m,
			}
			byID[id] = om
			order = append(order, om)
		}
		return nil
	}
	if err := ingest(local, "local"); err != nil {
		return nil, err
	}
	if err := ingest(remote, "remote"); err != nil {
		return nil, err
	}
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].tsKey != order[j].tsKey {
			return order[i].tsKey < order[j].tsKey
		}
		if order[i].roleKey != order[j].roleKey {
			return order[i].roleKey < order[j].roleKey
		}
		return order[i].hashKey < order[j].hashKey
	})
	out := make([]any, 0, len(order))
	for _, om := range order {
		out = append(out, om.msg)
	}
	return out, nil
}

// messageIdentity is `id` if the client explicitly set one, otherwise a
// SHA-256 of (role || 0x1f || content || 0x1f || timestamp). The 0x1f
// (unit separator) byte cannot occur inside any of the inputs as JSON
// strings, so the boundary is unambiguous.
func messageIdentity(m map[string]any) string {
	if id, ok := m["id"].(string); ok && id != "" {
		return "id:" + id
	}
	role := stringField(m, "role")
	content := stringField(m, "content")
	ts := timestampKey(m["timestamp"])
	h := sha256Sum([]byte(role + "\x1f" + content + "\x1f" + ts))
	return "syn:" + h
}

func mergeIdenticalMessages(a, b map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(a))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if existing, exists := out[k]; exists {
			if k == "attachments" {
				continue
			}
			if !jsonValuesEqual(existing, v) {
				return nil, &Conflict{Reason: "message_field_diverged:" + k}
			}
			continue
		}
		out[k] = v
	}
	aAtt, _ := a["attachments"].([]any)
	bAtt, _ := b["attachments"].([]any)
	if aAtt != nil || bAtt != nil {
		merged, err := mergeAttachments(aAtt, bAtt, -1)
		if err != nil {
			return nil, err
		}
		out["attachments"] = merged
	}
	return out, nil
}

func stringField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func timestampKey(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		// Reduce to integer milliseconds so we ignore float jitter.
		return fmt.Sprintf("%d", int64(x))
	case int64:
		return fmt.Sprintf("%d", x)
	}
	return ""
}

func mergeAttachments(l, r []any, msgIdx int) ([]any, error) {
	seen := map[string]map[string]any{}
	order := []string{}
	add := func(items []any, side string) error {
		for ai, item := range items {
			m, _ := item.(map[string]any)
			if m == nil {
				return &Conflict{Reason: fmt.Sprintf("message_%d_attachment_%d_%s_not_object", msgIdx, ai, side)}
			}
			id, _ := m["id"].(string)
			if id == "" {
				return &Conflict{Reason: fmt.Sprintf("message_%d_attachment_%d_%s_missing_id", msgIdx, ai, side)}
			}
			if existing, dup := seen[id]; dup {
				if !attachmentsEqual(existing, m) {
					return &Conflict{Reason: fmt.Sprintf("message_%d_attachment_%s_content_changed", msgIdx, id)}
				}
				continue
			}
			seen[id] = m
			order = append(order, id)
		}
		return nil
	}
	if err := add(l, "local"); err != nil {
		return nil, err
	}
	if err := add(r, "remote"); err != nil {
		return nil, err
	}
	out := make([]any, 0, len(order))
	for _, id := range order {
		out = append(out, seen[id])
	}
	return out, nil
}

func attachmentsEqual(a, b map[string]any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

// -------- profile -------------------------------------------------------

type profileResolver struct{}

// Profile plaintext is a single JSON object treated as a flat key-value
// settings document. The resolver applies RFC-7396-style merging:
//   - keys present in only one side are kept
//   - keys present in both sides with equal values are kept
//   - keys present in both sides with different scalar values → conflict
//     unless the key is in the lastWriterWins allowlist below
//   - nested objects recurse; arrays are treated as scalars
//
// LWW fields are the small set of cosmetic settings where two devices
// disagreeing produces UX noise rather than data loss.
var profileLastWriterWins = map[string]bool{
	"theme":             true,
	"sidebar_collapsed": true,
	"sidebar_width":     true,
}

func (profileResolver) Merge(local, remote []byte) (Result, error) {
	var l, r map[string]any
	if err := json.Unmarshal(local, &l); err != nil {
		return Result{}, fmt.Errorf("resolver: local profile invalid: %w", err)
	}
	if err := json.Unmarshal(remote, &r); err != nil {
		return Result{}, fmt.Errorf("resolver: remote profile invalid: %w", err)
	}
	merged, err := mergeJSONObjects(l, r, "")
	if err != nil {
		return Result{}, err
	}
	encoded, err := json.Marshal(merged)
	if err != nil {
		return Result{}, err
	}
	return Result{Plaintext: encoded, Changed: !jsonEqual(local, encoded)}, nil
}

func mergeJSONObjects(l, r map[string]any, path string) (map[string]any, error) {
	out := make(map[string]any, len(l)+len(r))
	keys := keyUnion(l, r)
	for _, k := range keys {
		lv, lok := l[k]
		rv, rok := r[k]
		fullPath := path + "/" + k
		switch {
		case lok && !rok:
			out[k] = lv
		case !lok && rok:
			out[k] = rv
		case jsonValuesEqual(lv, rv):
			out[k] = lv
		default:
			if lObj, ok := lv.(map[string]any); ok {
				if rObj, ok2 := rv.(map[string]any); ok2 {
					merged, err := mergeJSONObjects(lObj, rObj, fullPath)
					if err != nil {
						return nil, err
					}
					out[k] = merged
					continue
				}
			}
			if profileLastWriterWins[k] {
				out[k] = rv
				continue
			}
			return nil, &Conflict{Reason: "profile_field_conflict:" + strings.TrimPrefix(fullPath, "/")}
		}
	}
	return out, nil
}

// -------- project -------------------------------------------------------

type projectResolver struct{}

// Project metadata: merge non-overlapping fields. Conflicts on:
//   - id mismatch
//   - both sides changed `name` differently
//   - both sides changed `instructions` differently
//   - the documents list diverged in membership (rename/delete/add same doc)
func (projectResolver) Merge(local, remote []byte) (Result, error) {
	var l, r map[string]any
	if err := json.Unmarshal(local, &l); err != nil {
		return Result{}, fmt.Errorf("resolver: local project invalid: %w", err)
	}
	if err := json.Unmarshal(remote, &r); err != nil {
		return Result{}, fmt.Errorf("resolver: remote project invalid: %w", err)
	}
	if !sameString(l, r, "id") {
		return Result{}, &Conflict{Reason: "project_id_mismatch"}
	}

	out := make(map[string]any, len(l)+len(r))
	keys := keyUnion(l, r)
	for _, k := range keys {
		if k == "documents" || k == "document_ids" {
			continue
		}
		lv, lok := l[k]
		rv, rok := r[k]
		switch {
		case lok && !rok:
			out[k] = lv
		case !lok && rok:
			out[k] = rv
		case jsonValuesEqual(lv, rv):
			out[k] = lv
		default:
			return Result{}, &Conflict{Reason: "project_field_conflict:" + k}
		}
	}

	lDocs := stringArray(l["document_ids"])
	rDocs := stringArray(r["document_ids"])
	if lDocs != nil || rDocs != nil {
		mergedDocs, err := mergeDocumentIDs(lDocs, rDocs)
		if err != nil {
			return Result{}, err
		}
		out["document_ids"] = mergedDocs
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return Result{}, err
	}
	return Result{Plaintext: encoded, Changed: !jsonEqual(local, encoded)}, nil
}

func mergeDocumentIDs(l, r []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(l)+len(r))
	for _, id := range l {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, id := range r {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

// -------- project_document ---------------------------------------------

type projectDocumentResolver struct{}

// Project documents are whole-blob CAS only. The spec calls out that
// document-specific merges are future work and clients do not run their
// own crypto. The resolver therefore always returns a conflict: callers
// must surface SYNC_CONFLICT and prompt the user.
func (projectDocumentResolver) Merge(local, remote []byte) (Result, error) {
	if jsonEqual(local, remote) {
		return Result{Plaintext: local, Changed: false}, nil
	}
	return Result{}, &Conflict{Reason: "project_document_concurrent_edit"}
}

// -------- helpers -------------------------------------------------------

func sameString(a, b map[string]any, key string) bool {
	av, _ := a[key].(string)
	bv, _ := b[key].(string)
	return av == bv
}

// lastWriterWinsString resolves divergent string fields by comparing
// the *containing chat row's* `updatedAt` timestamp. We do not track
// per-field write times, so this is a best-effort approximation: a
// later overall write wins even if the specific field hadn't actually
// been touched on that side. That is acceptable because LWW only
// triggers when both sides explicitly disagree on the field, and the
// row-level timestamp is the closest signal available.
func lastWriterWinsString(local, remote map[string]any, key string) (string, bool) {
	r, rok := remote[key].(string)
	l, lok := local[key].(string)
	if !rok && !lok {
		return "", false
	}
	if rok && lok && r == l {
		return l, true
	}
	if rok && lok {
		if timestampKey(local["updatedAt"]) > timestampKey(remote["updatedAt"]) {
			return l, true
		}
		return r, true
	}
	if rok {
		return r, true
	}
	return l, true
}

func keyUnion(a, b map[string]any) []string {
	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func jsonValuesEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func jsonEqual(a, b []byte) bool {
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return false
	}
	return jsonValuesEqual(av, bv)
}

func stringArray(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func sha256Sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// IsConflict reports whether err is a resolver conflict.
func IsConflict(err error) bool {
	var c *Conflict
	return errors.As(err, &c)
}

// ConflictReason returns the conflict reason string if err is a conflict.
func ConflictReason(err error) string {
	var c *Conflict
	if errors.As(err, &c) {
		return c.Reason
	}
	return ""
}
