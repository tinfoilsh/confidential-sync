package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/importer"
)

const (
	nativeManifestPath    = "manifest.json"
	nativeManifestFormat  = "tinfoil-native-cloud-import"
	nativeManifestVersion = 1
	maxRestoreGenerations = 100
)

type nativeManifest struct {
	Format         string                 `json:"format"`
	Version        int                    `json:"version"`
	SourceBackupID string                 `json:"source_backup_id"`
	Counts         *nativeManifestCounts  `json:"counts,omitempty"`
	Entities       []nativeEntityManifest `json:"entities"`
	Blobs          []nativeBlobManifest   `json:"blobs"`
}

type nativeManifestCounts struct {
	Projects  int `json:"projects"`
	Documents int `json:"documents"`
	Chats     int `json:"chats"`
	Blobs     int `json:"blobs"`
}

type nativeEntityManifest struct {
	Kind            string `json:"kind"`
	SourceID        string `json:"source_id"`
	ProjectSourceID string `json:"project_source_id,omitempty"`
	Path            string `json:"path"`
	SHA256          string `json:"sha256"`
	SizeBytes       int64  `json:"size_bytes"`
}

type nativeBlobManifest struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type nativeProjectPayload struct {
	Name               string            `json:"name"`
	Description        string            `json:"description,omitempty"`
	SystemInstructions string            `json:"systemInstructions,omitempty"`
	Color              string            `json:"color,omitempty"`
	Memory             []json.RawMessage `json:"memory"`
}

type nativeDocumentPayload struct {
	Filename        string `json:"filename"`
	ContentType     string `json:"contentType"`
	SourceSizeBytes int64  `json:"sourceSizeBytes,omitempty"`
	SizeBytes       int64  `json:"sizeBytes"`
	Content         string `json:"content"`
}

type nativeChatPayload struct {
	Title       string                     `json:"title"`
	Messages    []nativeMessagePayload     `json:"messages"`
	CreatedAt   json.RawMessage            `json:"createdAt"`
	IsLocalOnly *bool                      `json:"isLocalOnly"`
	ProjectID   string                     `json:"projectId,omitempty"`
	Raw         map[string]json.RawMessage `json:"-"`
}

type nativeMessagePayload struct {
	Role             string                     `json:"role"`
	Content          string                     `json:"content"`
	Attachments      []nativeAttachmentPayload  `json:"attachments,omitempty"`
	Timestamp        json.RawMessage            `json:"timestamp"`
	Thoughts         string                     `json:"thoughts,omitempty"`
	ThinkingDuration json.Number                `json:"thinkingDuration,omitempty"`
	Raw              map[string]json.RawMessage `json:"-"`
}

type nativeAttachmentPayload struct {
	ID          string                     `json:"id,omitempty"`
	Type        importer.AttachmentType    `json:"type"`
	FileName    string                     `json:"fileName"`
	MimeType    string                     `json:"mimeType,omitempty"`
	TextContent string                     `json:"textContent,omitempty"`
	Description string                     `json:"description,omitempty"`
	FileSize    int64                      `json:"fileSize,omitempty"`
	ArchivePath string                     `json:"archivePath,omitempty"`
	Raw         map[string]json.RawMessage `json:"-"`
}

func (p *nativeChatPayload) UnmarshalJSON(data []byte) error {
	type known nativeChatPayload
	var value known
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &value.Raw); err != nil {
		return err
	}
	if raw, ok := value.Raw["title"]; ok {
		var title any
		if err := json.Unmarshal(raw, &title); err != nil {
			return err
		}
		if _, ok := title.(string); !ok {
			return errors.New("title must be a JSON string")
		}
	}
	*p = nativeChatPayload(value)
	return nil
}

func (p *nativeMessagePayload) UnmarshalJSON(data []byte) error {
	type known nativeMessagePayload
	var value known
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &value.Raw); err != nil {
		return err
	}
	if raw, ok := value.Raw["thinkingDuration"]; ok {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var duration any
		if err := decoder.Decode(&duration); err != nil {
			return err
		}
		if _, ok := duration.(json.Number); !ok {
			return errors.New("thinkingDuration must be a JSON number")
		}
	}
	*p = nativeMessagePayload(value)
	return nil
}

func (p *nativeAttachmentPayload) UnmarshalJSON(data []byte) error {
	type known nativeAttachmentPayload
	var value known
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &value.Raw); err != nil {
		return err
	}
	*p = nativeAttachmentPayload(value)
	return nil
}

type validatedNativeBackup struct {
	manifest  nativeManifest
	projects  []validatedNativeProject
	documents []validatedNativeDocument
	chats     []validatedNativeChat
	blobs     map[string]nativeBlobManifest
}

type validatedNativeProject struct {
	meta    nativeEntityManifest
	payload nativeProjectPayload
}

type validatedNativeDocument struct {
	meta    nativeEntityManifest
	payload nativeDocumentPayload
}

type validatedNativeChat struct {
	meta    nativeEntityManifest
	payload nativeChatPayload
}

func validateNativeBackup(arch *importArchive) (*validatedNativeBackup, error) {
	manifestBytes, err := arch.readEntry(nativeManifestPath, MaxImportJSONBytes)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(manifestBytes) {
		return nil, errors.New("import: manifest is not UTF-8")
	}
	var manifest nativeManifest
	if err := decodeStrictJSON(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("import: invalid manifest: %w", err)
	}
	if !hasJSONFields(manifestBytes, "format", "version", "source_backup_id", "counts", "entities", "blobs") || manifest.Counts == nil || manifest.Entities == nil || manifest.Blobs == nil {
		return nil, errors.New("import: manifest is missing required fields")
	}
	if manifest.Counts != nil {
		var manifestRoot map[string]json.RawMessage
		_ = json.Unmarshal(manifestBytes, &manifestRoot)
		if !hasJSONFields(manifestRoot["counts"], "projects", "documents", "chats", "blobs") {
			return nil, errors.New("import: manifest counts are incomplete")
		}
	}
	if manifest.Format != nativeManifestFormat || manifest.Version != nativeManifestVersion {
		return nil, errors.New("import: unsupported native backup format or version")
	}
	if strings.TrimSpace(manifest.SourceBackupID) == "" {
		return nil, errors.New("import: source_backup_id is required")
	}
	if manifest.Counts != nil && (manifest.Counts.Projects < 0 || manifest.Counts.Documents < 0 || manifest.Counts.Chats < 0 || manifest.Counts.Blobs < 0) {
		return nil, errors.New("import: invalid manifest counts")
	}
	if len(manifest.Entities) > MaxImportConversations || len(manifest.Blobs) > MaxImportAttachments {
		return nil, errors.New("import: native backup count limit exceeded")
	}

	out := &validatedNativeBackup{manifest: manifest, blobs: make(map[string]nativeBlobManifest)}
	listedPaths := map[string]bool{nativeManifestPath: true}
	entityIDs := make(map[string]bool)
	projectIDs := make(map[string]bool)
	var entityBytes int64
	var messages, attachments int

	for _, entity := range manifest.Entities {
		if entity.SourceID == "" || entity.Path == "" || !validSHA256(entity.SHA256) || entity.SizeBytes < 0 {
			return nil, errors.New("import: invalid entity descriptor")
		}
		name, ok := safeZipName(entity.Path)
		if !ok || name != entity.Path || listedPaths[name] {
			return nil, errors.New("import: invalid or duplicate listed path")
		}
		entity.Path = name
		listedPaths[name] = true
		entityKey := entity.Kind + "\x00" + entity.SourceID
		if entityIDs[entityKey] {
			return nil, errors.New("import: duplicate entity source id")
		}
		entityIDs[entityKey] = true
		if entity.Kind == "project" {
			if entity.ProjectSourceID != "" {
				return nil, errors.New("import: project cannot reference a parent project")
			}
			projectIDs[entity.SourceID] = true
		}

		data, err := arch.readEntry(name, MaxImportJSONBytes)
		if err != nil {
			return nil, err
		}
		entityBytes += int64(len(data))
		if entityBytes > MaxImportJSONBytes {
			return nil, errors.New("import: aggregate entity JSON exceeds size limit")
		}
		if err := validateListedData(data, entity.SizeBytes, entity.SHA256, true); err != nil {
			return nil, fmt.Errorf("import: entity %q: %w", entity.SourceID, err)
		}

		switch entity.Kind {
		case "project":
			var payload nativeProjectPayload
			if err := decodeStrictJSON(data, &payload); err != nil || !hasJSONFields(data, "name", "memory") || payload.Name == "" || payload.Memory == nil {
				return nil, errors.New("import: invalid project payload")
			}
			out.projects = append(out.projects, validatedNativeProject{meta: entity, payload: payload})
		case "document":
			if entity.ProjectSourceID == "" {
				return nil, errors.New("import: document project_source_id is required")
			}
			var payload nativeDocumentPayload
			if err := decodeStrictJSON(data, &payload); err != nil || !hasJSONFields(data, "filename", "contentType", "sourceSizeBytes", "sizeBytes", "content") || payload.Filename == "" || payload.ContentType == "" || payload.SizeBytes < 0 || payload.SourceSizeBytes < 0 {
				return nil, errors.New("import: invalid document payload")
			}
			out.documents = append(out.documents, validatedNativeDocument{meta: entity, payload: payload})
		case "chat":
			var payload nativeChatPayload
			if err := decodeStrictJSON(data, &payload); err != nil || !hasJSONFields(data, "title", "messages", "createdAt", "isLocalOnly") || payload.Messages == nil || payload.IsLocalOnly == nil {
				return nil, errors.New("import: invalid chat payload")
			}
			if *payload.IsLocalOnly {
				return nil, errors.New("import: local-only chats are not allowed")
			}
			if entity.ProjectSourceID == "" && payload.ProjectID != "" {
				return nil, errors.New("import: chat project reference must use project_source_id")
			}
			if entity.ProjectSourceID != "" && payload.ProjectID != "" && payload.ProjectID != entity.ProjectSourceID {
				return nil, errors.New("import: conflicting chat project reference")
			}
			for _, message := range payload.Messages {
				if message.Role == "" || !validJSONTime(message.Timestamp) {
					return nil, errors.New("import: invalid chat message")
				}
				messages++
				attachments += len(message.Attachments)
				for _, attachment := range message.Attachments {
					if attachment.Type != importer.AttachmentImage && attachment.Type != importer.AttachmentDocument {
						return nil, errors.New("import: invalid attachment type")
					}
					if attachment.FileName == "" || attachment.FileSize < 0 {
						return nil, errors.New("import: invalid attachment payload")
					}
					if attachment.Type == importer.AttachmentDocument && attachment.ArchivePath != "" {
						return nil, errors.New("import: binary document attachments are not supported")
					}
					if attachment.ArchivePath != "" {
						blobPath, ok := safeZipName(attachment.ArchivePath)
						if !ok || blobPath != attachment.ArchivePath {
							return nil, errors.New("import: invalid attachment archive path")
						}
					}
				}
			}
			if messages > MaxImportMessages || attachments > MaxImportAttachments {
				return nil, errors.New("import: native chat aggregate limit exceeded")
			}
			if !validJSONTime(payload.CreatedAt) {
				return nil, errors.New("import: invalid chat createdAt")
			}
			out.chats = append(out.chats, validatedNativeChat{meta: entity, payload: payload})
		default:
			return nil, errors.New("import: invalid entity kind")
		}
	}

	for _, blob := range manifest.Blobs {
		if blob.Path == "" || !validSHA256(blob.SHA256) || blob.SizeBytes < 0 || blob.SizeBytes > MaxImportAttachmentBytes {
			return nil, errors.New("import: invalid blob descriptor")
		}
		name, ok := safeZipName(blob.Path)
		if !ok || name != blob.Path || listedPaths[name] {
			return nil, errors.New("import: invalid or duplicate listed path")
		}
		blob.Path = name
		listedPaths[name] = true
		data, err := arch.readEntry(name, MaxImportAttachmentBytes)
		if err != nil {
			return nil, err
		}
		if err := validateListedData(data, blob.SizeBytes, blob.SHA256, false); err != nil {
			return nil, fmt.Errorf("import: blob %q: %w", name, err)
		}
		out.blobs[name] = blob
	}

	if manifest.Counts != nil && (manifest.Counts.Projects != len(out.projects) || manifest.Counts.Documents != len(out.documents) || manifest.Counts.Chats != len(out.chats) || manifest.Counts.Blobs != len(out.blobs)) {
		return nil, errors.New("import: manifest count mismatch")
	}
	for _, document := range out.documents {
		if !projectIDs[document.meta.ProjectSourceID] {
			return nil, errors.New("import: document references unknown project")
		}
	}
	for _, chat := range out.chats {
		if chat.meta.ProjectSourceID != "" && !projectIDs[chat.meta.ProjectSourceID] {
			return nil, errors.New("import: chat references unknown project")
		}
		for _, message := range chat.payload.Messages {
			for _, attachment := range message.Attachments {
				if attachment.ArchivePath != "" {
					if _, ok := out.blobs[attachment.ArchivePath]; !ok {
						return nil, errors.New("import: attachment references unknown blob")
					}
				}
			}
		}
	}
	for name := range arch.files {
		if !listedPaths[name] {
			return nil, fmt.Errorf("import: unlisted archive entry %q", name)
		}
	}
	return out, nil
}

func decodeStrictJSON(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func hasJSONFields(data []byte, fields ...string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil {
		return false
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validateListedData(data []byte, size int64, hash string, requireUTF8 bool) error {
	if int64(len(data)) != size {
		return errors.New("size mismatch")
	}
	if requireUTF8 && !utf8.Valid(data) {
		return errors.New("content is not UTF-8")
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), hash) {
		return errors.New("hash mismatch")
	}
	return nil
}

func validJSONTime(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	if bytes.Equal(raw, []byte("null")) {
		return true
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || value == "" {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}

func runNativeBackupImport(ctx context.Context, deps Deps, sess Session, job *ImportJobState, arch *importArchive, cekB64 string) error {
	job.setPhase("validating")
	backup, err := validateNativeBackup(arch)
	if err != nil {
		return err
	}

	projects := make(map[string]string)
	projectFailed := make(map[string]bool)
	projectCounts := ImportKindCounts{}
	job.setKindCount("project", projectCounts)
	job.setKindCount("document", ImportKindCounts{})
	job.setKindCount("chat", ImportKindCounts{})
	job.setPhase("projects")
	for _, project := range backup.projects {
		id, outcome, err := restoreNativeEntity(ctx, deps, sess, cekB64, backup.manifest.SourceBackupID, "project", project.meta.SourceID, "", func(id string, marker importer.RestoreMarker) ([]byte, map[string]any, []string, error) {
			payload := map[string]any{
				"id": id, "name": project.payload.Name, "description": project.payload.Description,
				"systemInstructions": project.payload.SystemInstructions, "color": project.payload.Color,
				"memory": project.payload.Memory, "_restore": marker,
			}
			body, err := json.Marshal(payload)
			return body, nil, nil, err
		})
		if err != nil {
			projectCounts.Failed++
			projectFailed[project.meta.SourceID] = true
			job.addError("project failed")
		} else {
			projects[project.meta.SourceID] = id
			job.setProjectMapping(project.meta.SourceID, id)
			incrementOutcome(&projectCounts, outcome)
		}
		job.setKindCount("project", projectCounts)
	}

	documentCounts := ImportKindCounts{}
	job.setPhase("documents")
	for _, document := range backup.documents {
		projectID, ok := projects[document.meta.ProjectSourceID]
		if !ok || projectFailed[document.meta.ProjectSourceID] {
			documentCounts.Blocked++
			job.setKindCount("document", documentCounts)
			continue
		}
		_, outcome, err := restoreNativeEntity(ctx, deps, sess, cekB64, backup.manifest.SourceBackupID, "document", document.meta.SourceID, projectID, func(id string, marker importer.RestoreMarker) ([]byte, map[string]any, []string, error) {
			payload := map[string]any{
				"id": id, "projectId": projectID, "filename": document.payload.Filename,
				"contentType": document.payload.ContentType, "sourceSizeBytes": document.payload.SourceSizeBytes,
				"sizeBytes": document.payload.SizeBytes, "content": document.payload.Content, "_restore": marker,
			}
			body, err := json.Marshal(payload)
			return body, nil, nil, err
		})
		if err != nil {
			documentCounts.Failed++
			job.addError("document failed")
		} else {
			incrementOutcome(&documentCounts, outcome)
		}
		job.setKindCount("document", documentCounts)
	}

	chatCounts := ImportKindCounts{}
	job.setPhase("chats")
	for _, chat := range backup.chats {
		projectID := ""
		if chat.meta.ProjectSourceID != "" {
			var ok bool
			projectID, ok = projects[chat.meta.ProjectSourceID]
			if !ok || projectFailed[chat.meta.ProjectSourceID] {
				chatCounts.Blocked++
				job.setKindCount("chat", chatCounts)
				continue
			}
		}
		_, outcome, err := restoreNativeEntity(ctx, deps, sess, cekB64, backup.manifest.SourceBackupID, "chat", chat.meta.SourceID, "", func(id string, marker importer.RestoreMarker) ([]byte, map[string]any, []string, error) {
			payload, attachmentIDs, err := buildNativeChatPayload(ctx, deps, sess, arch, backup, job, id, projectID, marker, chat.payload)
			metadata := map[string]any{"messageCount": len(chat.payload.Messages)}
			if projectID != "" {
				metadata["projectId"] = projectID
			}
			return payload, metadata, attachmentIDs, err
		})
		if err != nil {
			chatCounts.Failed++
			job.addError("chat failed")
		} else {
			incrementOutcome(&chatCounts, outcome)
		}
		job.setKindCount("chat", chatCounts)
	}

	imported := projectCounts.Imported + documentCounts.Imported + chatCounts.Imported
	failed := projectCounts.Failed + documentCounts.Failed + chatCounts.Failed
	total := len(backup.projects) + len(backup.documents) + len(backup.chats)
	job.setProgress(imported, failed, total)
	job.setPhase("complete")
	notifyImportComplete(ctx, deps, sess.Claims.Subject, job.ID, job.Source, imported, failed)
	return nil
}

type restoreOutcome int

const (
	restoreImported restoreOutcome = iota
	restoreSkipped
)

func incrementOutcome(counts *ImportKindCounts, outcome restoreOutcome) {
	if outcome == restoreSkipped {
		counts.Skipped++
	} else {
		counts.Imported++
	}
}

func restoreNativeEntity(ctx context.Context, deps Deps, sess Session, cekB64, backupID, kind, sourceID, projectID string, build func(string, importer.RestoreMarker) ([]byte, map[string]any, []string, error)) (string, restoreOutcome, error) {
	scope := kind
	if kind == "document" {
		scope = "project_document"
	}
	for generation := 0; generation < maxRestoreGenerations; generation++ {
		mappedID := mappedRestoreID(sess.Claims.Subject, backupID, kind, sourceID, generation)
		rowID := mappedID
		if kind == "document" {
			rowID = projectID + "/" + mappedID
		}
		marker := importer.RestoreMarker{Format: nativeManifestFormat, SourceBackupID: backupID, Kind: kind, SourceID: sourceID, Generation: generation}
		match, occupied, err := inspectRestoreCandidate(ctx, deps, sess, cekB64, scope, rowID, marker)
		if err != nil {
			return "", restoreImported, err
		}
		if match {
			return mappedID, restoreSkipped, nil
		}
		if occupied {
			continue
		}
		plaintext, metadata, attachmentIDs, err := build(mappedID, marker)
		if err != nil {
			cleanupNativeAttachments(ctx, deps, sess, attachmentIDs)
			return "", restoreImported, err
		}
		_, err = Push(ctx, deps, sess, PushRequest{
			Scope: scope, ID: rowID, Key: cekB64, Plaintext: base64.StdEncoding.EncodeToString(plaintext),
			IdempotencyKey: restoreIdemKey(sess.Claims.Subject, backupID, kind, sourceID, generation), Metadata: metadata,
		})
		if err == nil {
			return mappedID, restoreImported, nil
		}
		match, _, verifyErr := inspectRestoreCandidate(ctx, deps, sess, cekB64, scope, rowID, marker)
		if verifyErr != nil {
			return "", restoreImported, err
		}
		if match {
			if isAlreadyImported(err) {
				return mappedID, restoreSkipped, nil
			}
			return mappedID, restoreImported, nil
		}
		cleanupNativeAttachments(ctx, deps, sess, attachmentIDs)
		if isAlreadyImported(err) {
			continue
		}
		return "", restoreImported, err
	}
	return "", restoreImported, errors.New("import: restore id generations exhausted")
}

func inspectRestoreCandidate(ctx context.Context, deps Deps, sess Session, cekB64, scope, id string, marker importer.RestoreMarker) (match, occupied bool, err error) {
	resp, err := Pull(ctx, deps, sess, PullRequest{Scope: scope, IDs: []string{id}, Keys: []PullKey{{Key: cekB64}}})
	if err != nil {
		return false, false, err
	}
	if len(resp.Items) != 1 {
		return false, false, errors.New("import: invalid restore collision response")
	}
	item := resp.Items[0]
	if !item.OK {
		if item.Code == "NOT_FOUND" {
			return false, false, nil
		}
		if item.Code == CodeNetwork {
			return false, false, errors.New("import: restore collision check failed")
		}
		return false, true, nil
	}
	plaintext, err := base64.StdEncoding.DecodeString(item.Plaintext)
	if err != nil {
		return false, true, nil
	}
	var payload struct {
		Restore importer.RestoreMarker `json:"_restore"`
	}
	if json.Unmarshal(plaintext, &payload) != nil {
		return false, true, nil
	}
	return payload.Restore == marker, true, nil
}

func mappedRestoreID(userID, backupID, kind, sourceID string, generation int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("tinfoil-restore-id-v1\x00%s\x00%s\x00%s\x00%s\x00%d", userID, backupID, kind, sourceID, generation)))
	h := hex.EncodeToString(sum[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

func restoreIdemKey(userID, backupID, kind, sourceID string, generation int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("tinfoil-restore-write-v1\x00%s\x00%s\x00%s\x00%s\x00%d", userID, backupID, kind, sourceID, generation)))
	return hex.EncodeToString(sum[:16])
}

func buildNativeChatPayload(ctx context.Context, deps Deps, sess Session, arch *importArchive, backup *validatedNativeBackup, job *ImportJobState, chatID, projectID string, marker importer.RestoreMarker, input nativeChatPayload) ([]byte, []string, error) {
	messages := make([]map[string]json.RawMessage, 0, len(input.Messages))
	attachmentIndex := 0
	var attachmentIDs []string
	for _, message := range input.Messages {
		out := cloneRawMap(message.Raw)
		attachments := make([]map[string]json.RawMessage, 0, len(message.Attachments))
		for _, attachment := range message.Attachments {
			stored := cloneRawMap(attachment.Raw)
			delete(stored, "archivePath")
			delete(stored, "backup_path")
			delete(stored, "base64")
			delete(stored, "thumbnailBase64")
			delete(stored, "encryptionKey")
			delete(stored, "key")
			if attachment.Type == importer.AttachmentImage {
				blob, listed := backup.blobs[attachment.ArchivePath]
				if attachment.ArchivePath == "" || !listed {
					job.addWarning("image attachment blob missing")
					continue
				}
				data, err := arch.readEntry(blob.Path, MaxImportAttachmentBytes)
				if err != nil || validateListedData(data, blob.SizeBytes, blob.SHA256, false) != nil {
					job.addWarning("image attachment blob invalid")
					continue
				}
				contentType := http.DetectContentType(data)
				if !allowedImageMIME(contentType) {
					job.addWarning("image attachment type rejected")
					continue
				}
				putResp, err := AttachmentPut(ctx, deps, sess, AttachmentPutRequest{
					ChatID: chatID, Plaintext: base64.StdEncoding.EncodeToString(data),
					IdempotencyKey: attachmentIdemKey(chatID, attachment.ArchivePath, attachmentIndex),
				})
				attachmentIndex++
				if err != nil {
					job.addWarning("image attachment upload failed")
					continue
				}
				setRawString(stored, "id", putResp.ID)
				attachmentIDs = append(attachmentIDs, putResp.ID)
				setRawString(stored, "encryptionKey", putResp.AttKey)
				setRawString(stored, "mimeType", contentType)
			}
			attachments = append(attachments, stored)
		}
		if len(attachments) > 0 {
			if err := setRawJSON(out, "attachments", attachments); err != nil {
				return nil, attachmentIDs, err
			}
		} else {
			delete(out, "attachments")
		}
		messages = append(messages, out)
	}
	payload := cloneRawMap(input.Raw)
	for _, field := range []string{
		"clock", "clockVersion", "codeExecutionAccessToken", "dataCorrupted", "decryptionFailed",
		"formatVersion", "isBlankChat", "isMetadataOnly", "isTemporary", "lastAccessedAt", "loadedAt",
		"locallyModified", "messageCount", "pendingRecoveries", "pendingSave", "pendingUpload",
		"projectLocallyModified", "syncPending", "syncUserId", "syncedAt", "syncVersion", "version", "writer",
	} {
		delete(payload, field)
	}
	setRawString(payload, "id", chatID)
	if err := setRawJSON(payload, "messages", messages); err != nil {
		return nil, attachmentIDs, err
	}
	payload["isLocalOnly"] = json.RawMessage("false")
	if err := setRawJSON(payload, "_restore", marker); err != nil {
		return nil, attachmentIDs, err
	}
	if projectID != "" {
		setRawString(payload, "projectId", projectID)
	} else {
		delete(payload, "projectId")
	}
	body, err := json.Marshal(payload)
	return body, attachmentIDs, err
}

func cloneRawMap(input map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func setRawJSON(payload map[string]json.RawMessage, name string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	payload[name] = encoded
	return nil
}

func setRawString(payload map[string]json.RawMessage, name, value string) {
	payload[name] = json.RawMessage(strconv.Quote(value))
}

func cleanupNativeAttachments(ctx context.Context, deps Deps, sess Session, attachmentIDs []string) {
	if len(attachmentIDs) == 0 {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bucketsRollbackTimeout)
	defer cancel()
	for _, attachmentID := range attachmentIDs {
		if err := deps.Controlplane.DeleteAttachmentIndex(cleanupCtx, sess.RawJWT, sess.Claims.Subject, attachmentID); err != nil {
			deps.logError("native import attachment index cleanup failed: user=%s att=%s err=%v", sess.Claims.Subject, attachmentID, err)
			continue
		}
		if deps.Buckets != nil && deps.Buckets.Configured() {
			if err := deps.Buckets.Delete(cleanupCtx, sess.Claims.Subject, attachmentID); err != nil {
				deps.logError("native import attachment blob cleanup failed: user=%s att=%s err=%v", sess.Claims.Subject, attachmentID, err)
			}
		}
	}
}
