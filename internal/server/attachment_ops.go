package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
)

// bucketsRollbackTimeout caps the best-effort cleanup that runs
// after a successful buckets Put but a failed controlplane index.
// Because the rollback runs on a context detached from the request
// (so client cancellation can't skip it), it needs its own bounded
// deadline — otherwise a hung buckets backend would pin the
// handler well past the request budget.
const bucketsRollbackTimeout = 30 * time.Second

// attKeySize is the length of the per-attachment AES-256 key the
// enclave derives on upload and hands to the webapp. Matches buckets'
// required slot key size.
const attKeySize = 32

// AttachmentPutRequest carries a single attachment upload. The
// plaintext lives on the wire only on the webapp↔enclave hop; the
// enclave derives a per-attachment AES-256 key, hands the
// plaintext + that key to buckets (buckets seals natively under its
// v1 envelope), registers ownership with the controlplane, and
// returns the key to the webapp so it can be embedded in the chat
// JSON under `attachments[i].encryptionKey`.
//
// The webapp never picks the attachment id: the enclave derives it
// from the caller idempotency key, user, chat, and plaintext, then
// returns it. This keeps retries stable while preserving enclave
// control of buckets paths and the controlplane attachment index.
// a new row gets. No CEK material flows on this request — the
// per-attachment key is what protects the buckets bytes, and the
// chat envelope (sealed under CEK) is what protects the
// per-attachment key.
type AttachmentPutRequest struct {
	ChatID    string `json:"chat_id"`
	Plaintext string `json:"plaintext"` // base64 attachment bytes
	// IdempotencyKey is the caller's required anti-duplication tag.
	// The enclave deterministically derives the attachment id and
	// per-attachment key from it (via HKDF over the user's Clerk
	// subject so two users with colliding ids still hit different
	// buckets slots), so a retried upload produces the same
	// (id, att_key) and the same buckets bytes — no orphans.
	IdempotencyKey string `json:"idempotency_key"`
}

// AttachmentPutResponse confirms the bucket write + index
// registration and surfaces the enclave-minted attachment id plus
// the per-attachment key the caller must embed in the chat JSON so
// future reads can unlock the bucket entry.
type AttachmentPutResponse struct {
	OK     bool   `json:"ok"`
	ID     string `json:"id"`
	AttKey string `json:"att_key"` // base64 32-byte AES-256 key
}

const (
	attachmentIDBytes = 18
)

const (
	attachmentIDInfo  = "tinfoil-attachment-id-v1"
	attachmentKeyInfo = "tinfoil-attachment-key-v1"
)

// deriveAttachmentMaterials reproduces the (id, slot key) pair from
// a caller-supplied idempotency key, the chat id it belongs to, the
// clerk subject, and a digest of the plaintext bytes. Binding the
// derivation to all four inputs means:
//
//   - A true retry (same user, same chat, same key, same bytes)
//     produces the same (id, att_key) and is a true no-op against
//     buckets.
//   - A reused key with different bytes (caller bug or attacker
//     replaying a captured idempotency tag) derives a different id,
//     so it cannot overwrite the original attachment's slot.
//   - A reused key from a different chat or a different user
//     likewise derives a different id, so per-chat / per-user
//     ownership stays intact.
func deriveAttachmentMaterials(idempotencyKey, chatID, clerkSubject string, plaintext []byte) (string, []byte, error) {
	if idempotencyKey == "" {
		return "", nil, errors.New("idempotency key is required")
	}
	if chatID == "" {
		return "", nil, errors.New("chat id is required")
	}
	plaintextDigest := sha256.Sum256(plaintext)
	// IKM components are length-prefixed (8-byte big-endian) so the
	// derivation is unambiguous regardless of what bytes the inputs
	// contain. A printable delimiter like "|" would collide on
	// inputs that themselves contain that character
	// (e.g. ("a|b","c") and ("a","b|c") would produce identical IKM
	// and thus identical (id, key) pairs); a NUL delimiter would
	// rule out one byte but JSON strings can carry NUL through
	// `\u0000`. Length-prefixing is the standard
	// domain-separation construction and has no string-injection
	// failure mode.
	//
	// COMPAT NOTE: changing the IKM encoding after this code has
	// shipped to production breaks idempotent retries across the
	// deploy boundary (old enclave derived id A; new enclave
	// derives id B for the same input; both end up in buckets and
	// the chat JSON only references one of them, orphaning the
	// other). The attachment feature has not yet been released, so
	// the current rewrite is safe; any future format change must
	// dual-derive on read and ship the format flip behind a
	// compat window long enough to drain in-flight retries.
	ikm := encodeIKM(idempotencyKey, chatID, clerkSubject, hex.EncodeToString(plaintextDigest[:]))
	idBytes := make([]byte, attachmentIDBytes)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, nil, []byte(attachmentIDInfo)), idBytes); err != nil {
		return "", nil, err
	}
	key := make([]byte, attKeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, nil, []byte(attachmentKeyInfo)), key); err != nil {
		cryptopkg.Zero(key)
		return "", nil, err
	}
	return hex.EncodeToString(idBytes), key, nil
}

// encodeIKM concatenates the provided components using length
// prefixes for unambiguous domain separation. Each component is
// emitted as a big-endian uint64 byte-length followed by its bytes;
// no separator can collide with input bytes because the length
// uniquely identifies each field boundary.
func encodeIKM(parts ...string) []byte {
	total := 0
	for _, p := range parts {
		total += 8 + len(p)
	}
	buf := make([]byte, 0, total)
	var lenBuf [8]byte
	for _, p := range parts {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(p)))
		buf = append(buf, lenBuf[:]...)
		buf = append(buf, p...)
	}
	return buf
}

// AttachmentGetRequest carries an attachment fetch. The webapp
// pulls the per-attachment key out of the chat JSON (where it
// lives in `attachments[i].encryptionKey`) and supplies it here;
// the enclave forwards it to buckets as the slot key.
type AttachmentGetRequest struct {
	ID     string `json:"id"`
	AttKey string `json:"att_key"` // base64 32-byte AES-256 key
}

// AttachmentGetResponse returns base64 plaintext.
type AttachmentGetResponse struct {
	OK        bool   `json:"ok"`
	Plaintext string `json:"plaintext"`
}

type AttachmentDeleteRequest struct {
	ID string `json:"id"`
}

// AttachmentPut uploads an attachment plaintext to buckets under a
// per-attachment key derived from the idempotency key. The key is
// returned so the caller can embed it in the chat JSON; nothing about
// the key is persisted by the enclave itself.
func AttachmentPut(ctx context.Context, deps Deps, sess Session, req AttachmentPutRequest) (*AttachmentPutResponse, error) {
	if deps.Buckets == nil || !deps.Buckets.Configured() {
		return nil, &AppError{Status: 503, Code: CodeInternal, Message: "buckets backend not configured"}
	}
	if req.ChatID == "" {
		return nil, badRequest("chat_id is required")
	}
	if req.IdempotencyKey == "" {
		return nil, badRequest("idempotency_key is required")
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		return nil, badRequest("invalid plaintext base64")
	}
	defer cryptopkg.Zero(plaintext)

	var (
		id     string
		attKey []byte
	)
	// Deterministic derivation: any retry of the same upload
	// (same user, same chat, same key, same bytes) resolves to
	// the same id+key. The buckets Put under that pair is
	// idempotent (same value, same slot key), and the
	// controlplane index registration is safe to repeat. Mixing
	// chat_id + plaintext digest into the IKM ensures a
	// caller-side bug that reuses the key for different content
	// or a different chat lands on a fresh slot instead of
	// silently overwriting the original attachment.
	id, attKey, err = deriveAttachmentMaterials(req.IdempotencyKey, req.ChatID, sess.Claims.Subject, plaintext)
	if err != nil {
		return nil, &AppError{Status: 500, Code: CodeInternal, Message: "derive attachment materials: " + err.Error()}
	}
	defer cryptopkg.Zero(attKey)

	deps.logInfo("attachment put begin: user=%s chat=%s att=%s plaintext_bytes=%d",
		sess.Claims.Subject, req.ChatID, id, len(plaintext))

	// Stamp the pending-write guard before touching buckets. If the
	// reservation itself fails (CP unreachable) we surface immediately
	// rather than risk a buckets write the sweeper can never see; the
	// caller retries the whole upload. Idempotent on retry.
	if err := deps.Controlplane.ReservePendingAttachmentWrite(ctx, sess.RawJWT, id, req.ChatID); err != nil {
		deps.logError("attachment put reserve failed: user=%s chat=%s att=%s err=%v",
			sess.Claims.Subject, req.ChatID, id, err)
		return nil, &AppError{Status: 502, Code: CodeUpstream, Message: "controlplane reserve failed: " + err.Error()}
	}
	if err := deps.Buckets.Put(ctx, id, plaintext, attKey); err != nil {
		deps.logError("attachment put buckets failed: user=%s chat=%s att=%s err=%v",
			sess.Claims.Subject, req.ChatID, id, err)
		return nil, &AppError{Status: 502, Code: CodeUpstream, Message: "buckets put failed: " + err.Error()}
	}
	if err := deps.Controlplane.RegisterAttachmentIndex(ctx, sess.RawJWT, id, req.ChatID); err != nil {
		// Only roll back when we have a structured 4xx response from
		// the controlplane — that's the one signal that proves the
		// index row was NOT committed. Transport errors, context
		// cancellation, and 5xx are all ambiguous: the controlplane
		// may already hold an index entry pointing at this bucket
		// id, in which case a rollback would silently delete a row
		// the user still owns. The orphan reaper is the correct
		// path for those ambiguous cases — it cross-checks the
		// controlplane index of record before reaping any bucket.
		if isControlplaneRejection(err) {
			deps.logError("attachment put index rejected, rolling back buckets: user=%s chat=%s att=%s err=%v",
				sess.Claims.Subject, req.ChatID, id, err)
			// Detach from the request context so a client cancellation
			// does not also skip the cleanup it triggered, but enforce
			// a fresh bounded deadline so a hung buckets backend
			// cannot pin this handler past the request budget.
			func() {
				rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bucketsRollbackTimeout)
				defer cancel()
				_ = deps.Buckets.Delete(rollbackCtx, id)
			}()
		} else {
			deps.logError("attachment put index failed (ambiguous, deferring to reaper): user=%s chat=%s att=%s err=%v",
				sess.Claims.Subject, req.ChatID, id, err)
		}
		return nil, &AppError{Status: 502, Code: CodeUpstream, Message: "controlplane index failed: " + err.Error()}
	}
	deps.logInfo("attachment put ok: user=%s chat=%s att=%s",
		sess.Claims.Subject, req.ChatID, id)
	return &AttachmentPutResponse{
		OK:     true,
		ID:     id,
		AttKey: base64.StdEncoding.EncodeToString(attKey),
	}, nil
}

// AttachmentGet fetches an attachment by id using the per-attachment
// key the caller supplies. A buckets 404 surfaces as a 404 to the
// webapp so the legacy fallback path can run. A buckets 403 (slot key
// mismatch) surfaces as a 400 — the caller has the wrong key for the
// id, which is unrecoverable without a fresh chat pull.
//
// AttachmentGet is intentionally session-agnostic: knowing the
// attachment id + the per-attachment key is the access proof. The
// same handler runs for the owner (authenticated `/v1/attachment/get`)
// and for share recipients (unauthenticated `/v1/attachment/get-public`)
// because the trust model is identical in both cases — the bucket
// entry's slot key is the only credential, and it lives in the
// chat/share JSON the caller already holds.
func AttachmentGet(ctx context.Context, deps Deps, req AttachmentGetRequest) (*AttachmentGetResponse, error) {
	if deps.Buckets == nil || !deps.Buckets.Configured() {
		return nil, &AppError{Status: 503, Code: CodeInternal, Message: "buckets backend not configured"}
	}
	if req.ID == "" {
		return nil, badRequest("id is required")
	}
	attKey, err := base64.StdEncoding.DecodeString(req.AttKey)
	if err != nil {
		return nil, badRequest("invalid att_key base64")
	}
	defer cryptopkg.Zero(attKey)
	if len(attKey) != attKeySize {
		return nil, badRequest("att_key must be 32 bytes")
	}

	deps.logInfo("attachment get begin: att=%s", req.ID)
	plaintext, err := deps.Buckets.Get(ctx, req.ID, attKey)
	if err != nil {
		if errors.Is(err, buckets.ErrNotFound) {
			deps.logInfo("attachment get not-found: att=%s", req.ID)
			return nil, &AppError{Status: 404, Code: CodeNotFound, Message: "attachment not found"}
		}
		if errors.Is(err, buckets.ErrForbidden) {
			deps.logInfo("attachment get forbidden (key mismatch): att=%s", req.ID)
			return nil, badRequest("attachment key does not match")
		}
		deps.logError("attachment get failed: att=%s err=%v", req.ID, err)
		return nil, &AppError{Status: 502, Code: CodeUpstream, Message: "buckets get failed: " + err.Error()}
	}
	defer cryptopkg.Zero(plaintext)
	deps.logInfo("attachment get ok: att=%s plaintext_bytes=%d", req.ID, len(plaintext))
	return &AttachmentGetResponse{
		OK:        true,
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}, nil
}

// isControlplaneRejection reports whether `err` is a structured 4xx
// response from the controlplane. Only those errors prove the
// request did NOT mutate state on the server, so they're the only
// safe trigger for an inline buckets rollback. Anything else
// (transport failures, context cancellation, 5xx) leaves the
// commit status ambiguous and must defer to the orphan reaper.
func isControlplaneRejection(err error) bool {
	var cpe *controlplane.Error
	if !errors.As(err, &cpe) {
		return false
	}
	return cpe.StatusCode >= 400 && cpe.StatusCode < 500
}

func AttachmentDelete(ctx context.Context, deps Deps, sess Session, req AttachmentDeleteRequest) (*OKResponse, error) {
	if req.ID == "" {
		return nil, badRequest("id is required")
	}
	deps.logInfo("attachment delete begin: user=%s att=%s",
		sess.Claims.Subject, req.ID)
	// Controlplane delete runs first because it is the ownership
	// check: it rejects callers who don't own the attachment id,
	// which is what stops an authenticated attacker from
	// weaponizing the bucket-delete path against victim ids they
	// might have observed in a shared chat.
	if err := deps.Controlplane.DeleteAttachmentIndex(ctx, sess.RawJWT, req.ID); err != nil {
		var cpe *controlplane.Error
		if errors.As(err, &cpe) && cpe.StatusCode == 404 {
			deps.logInfo("attachment delete not-found: user=%s att=%s",
				sess.Claims.Subject, req.ID)
			return nil, &AppError{Status: 404, Code: CodeNotFound, Message: "attachment not found"}
		}
		deps.logError("attachment delete index failed: user=%s att=%s err=%v",
			sess.Claims.Subject, req.ID, err)
		return nil, &AppError{Status: 502, Code: CodeUpstream, Message: "controlplane attachment delete failed: " + err.Error()}
	}
	// The bucket delete must succeed for the user's "delete this
	// attachment" intent to actually land — a leaked bucket entry
	// stays readable by anyone holding (id, att_key), so swallowing
	// the failure would silently keep the bytes online after we
	// reported success. Surface it as 502 so the caller can retry;
	// buckets.Delete is idempotent on 404, so a retry after the
	// controlplane index is already gone still cleans up safely.
	if deps.Buckets != nil && deps.Buckets.Configured() {
		if err := deps.Buckets.Delete(ctx, req.ID); err != nil {
			deps.logError("attachment delete buckets failed: user=%s att=%s err=%v",
				sess.Claims.Subject, req.ID, err)
			return nil, &AppError{Status: 502, Code: CodeUpstream, Message: "buckets attachment delete failed: " + err.Error()}
		}
	}
	deps.logInfo("attachment delete ok: user=%s att=%s",
		sess.Claims.Subject, req.ID)
	return &OKResponse{OK: true}, nil
}
