package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/importer"
)

type nativeTestEntity struct {
	kind            string
	sourceID        string
	projectSourceID string
	path            string
	payload         []byte
}

func TestNativeBackupRestoresGraphAttachmentsAndSkipsRetry(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x42}, 64)...)
	archive := nativeTestArchive(t, "backup-1", []nativeTestEntity{
		{kind: "project", sourceID: "p1", path: "entities/project.json", payload: []byte(`{"name":"Research","description":"notes","systemInstructions":"be exact","color":"blue","memory":[{"id":"fact-1","fact":"facts","date":"2024-01-01T00:00:00.000Z","category":"note","confidence":1}]}`)},
		{kind: "document", sourceID: "d1", projectSourceID: "p1", path: "entities/document.json", payload: []byte(`{"filename":"brief.txt","contentType":"text/plain","sourceSizeBytes":5,"sizeBytes":5,"content":"hello"}`)},
		{kind: "chat", sourceID: "c1", projectSourceID: "p1", path: "entities/chat.json", payload: []byte(`{"title":"Plan","messages":[{"role":"user","content":"look","timestamp":"2024-01-01T00:00:00.000Z","attachments":[{"type":"image","fileName":"image.png","mimeType":"image/png","fileSize":72,"archivePath":"blobs/image.png"}]}],"createdAt":"2024-01-01T00:00:00.000Z","isLocalOnly":false}`)},
	}, map[string][]byte{"blobs/image.png": png}, nil)

	job := runNativeTestArchive(t, f, archive)
	snap := job.Snapshot()
	if snap.Imported != 3 || snap.Failed != 0 || snap.Counts["project"].Imported != 1 || snap.Counts["document"].Imported != 1 || snap.Counts["chat"].Imported != 1 {
		t.Fatalf("unexpected first import status: %+v", snap)
	}
	projectID := mappedRestoreID(f.userSub, "backup-1", "project", "p1", 0)
	documentID := mappedRestoreID(f.userSub, "backup-1", "document", "d1", 0)
	chatID := mappedRestoreID(f.userSub, "backup-1", "chat", "c1", 0)
	if f.cp.blobs["project/"+projectID] == nil || f.cp.blobs["project_document/"+projectID+"/"+documentID] == nil || f.cp.blobs["chat/"+chatID] == nil {
		t.Fatal("expected mapped project, document, and chat rows")
	}
	chatBlob := f.cp.blobs["chat/"+chatID]
	if !chatBlob.ProjectIDSet || chatBlob.ProjectID == nil || *chatBlob.ProjectID != projectID {
		t.Fatalf("chat metadata project id was not mapped: %+v", chatBlob)
	}
	if len(f.cp.attachmentIndex) != 1 {
		t.Fatalf("expected one restored attachment, got %d", len(f.cp.attachmentIndex))
	}
	chatPayload := decryptNativeTestBlob(t, f, "chat", chatID)
	if chatPayload["projectId"] != projectID || chatPayload["_restore"] == nil {
		t.Fatalf("restored chat payload is missing mapped metadata: %+v", chatPayload)
	}
	projectPayload := decryptNativeTestBlob(t, f, "project", projectID)
	if memory, ok := projectPayload["memory"].([]any); !ok || len(memory) != 1 {
		t.Fatalf("project memory was not preserved as an array: %+v", projectPayload["memory"])
	}
	if snap.ProjectMappings["p1"] != projectID {
		t.Fatalf("project mapping missing from status: %+v", snap.ProjectMappings)
	}

	retry := runNativeTestArchive(t, f, archive)
	retrySnap := retry.Snapshot()
	if retrySnap.Imported != 0 || retrySnap.Counts["project"].Skipped != 1 || retrySnap.Counts["document"].Skipped != 1 || retrySnap.Counts["chat"].Skipped != 1 {
		t.Fatalf("unexpected retry status: %+v", retrySnap)
	}
	if len(f.cp.blobs) != 3 || len(f.cp.attachmentIndex) != 1 {
		t.Fatal("retry should not create additional rows or attachments")
	}
}

func TestNativeCloudContractFixturePassesValidation(t *testing.T) {
	fixtureBytes, err := os.ReadFile("testdata/native-cloud-import-v1.zip")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(fixtureBytes), int64(len(fixtureBytes)))
	if err != nil {
		t.Fatal(err)
	}
	arch := &importArchive{zr: zr, files: make(map[string]*zip.File)}
	if err := arch.validateAndIndex(string(importer.SourceTinfoilBackup)); err != nil {
		t.Fatal(err)
	}
	validated, err := validateNativeBackup(arch)
	if err != nil {
		t.Fatalf("web contract fixture failed validation: %v", err)
	}
	if validated.manifest.Format != "tinfoil-native-cloud-import" || validated.manifest.Version != 1 || validated.manifest.SourceBackupID != "123e4567-e89b-42d3-a456-426614174000" {
		t.Fatalf("unexpected native manifest identity: %+v", validated.manifest)
	}
	if got, want := *validated.manifest.Counts, (nativeManifestCounts{Projects: 1, Documents: 1, Chats: 1, Blobs: 1}); got != want {
		t.Fatalf("manifest counts = %+v, want %+v", got, want)
	}
	if len(validated.projects) != 1 || len(validated.documents) != 1 || len(validated.chats) != 1 || len(validated.blobs) != 1 {
		t.Fatalf("unexpected validated fixture: %+v", validated)
	}
	wantEntities := []nativeEntityManifest{
		{Kind: "project", SourceID: "project-1", Path: "entities/project/0.json", SHA256: "efb9e21973107e4daa8e5c4204ac685ac25a25d986085bdeb10995c91533b9bf", SizeBytes: 109},
		{Kind: "document", SourceID: "document-1", ProjectSourceID: "project-1", Path: "entities/document/1.json", SHA256: "6c4e16caa87568c13a4d9f83171c8f4298f3920ec839150b7321f762d4cc9f73", SizeBytes: 123},
		{Kind: "chat", SourceID: "cloud-1", ProjectSourceID: "project-1", Path: "entities/chat/2.json", SHA256: "4111fbb0e8525ab74c8904fc48c18a606333992731cec7e1ef7e34c834963db3", SizeBytes: 387},
	}
	if !reflect.DeepEqual(validated.manifest.Entities, wantEntities) {
		t.Fatalf("entity descriptors = %+v, want %+v", validated.manifest.Entities, wantEntities)
	}
	project := validated.projects[0]
	if project.meta.SourceID != "project-1" || project.payload.Name != "Research" || project.payload.Description != "Description" || project.payload.SystemInstructions != "Be exact" || project.payload.Color != "#123456" || len(project.payload.Memory) != 0 {
		t.Fatalf("unexpected project contract: %+v", project)
	}
	document := validated.documents[0]
	if document.meta.SourceID != "document-1" || document.meta.ProjectSourceID != "project-1" || document.payload.Filename != "paper.pdf" || document.payload.ContentType != "application/pdf" || document.payload.SourceSizeBytes != 9000 || document.payload.SizeBytes != 9000 || document.payload.Content != "Extracted text" {
		t.Fatalf("unexpected document contract: %+v", document)
	}
	chat := validated.chats[0]
	if chat.meta.SourceID != "cloud-1" || chat.meta.ProjectSourceID != "project-1" || chat.payload.Title != "Cloud chat" || chat.payload.ProjectID != "" || chat.payload.IsLocalOnly == nil || *chat.payload.IsLocalOnly || len(chat.payload.Messages) != 1 {
		t.Fatalf("unexpected chat contract: %+v", chat)
	}
	for field, want := range map[string]string{"titleState": `"manual"`, "model": `"gpt-oss-120b"`} {
		if got := string(chat.payload.Raw[field]); got != want {
			t.Fatalf("chat field %s = %s, want %s", field, got, want)
		}
	}
	message := chat.payload.Messages[0]
	if message.Role != "user" || message.Content != "hello" || string(message.Timestamp) != `"2026-08-20T12:00:00.000Z"` || len(message.Attachments) != 1 {
		t.Fatalf("unexpected message contract: %+v", message)
	}
	attachment := message.Attachments[0]
	if attachment.ID != "cloud-image" || attachment.Type != importer.AttachmentImage || attachment.FileName != "photo.png" || attachment.MimeType != "image/png" || attachment.FileSize != 72 || attachment.ArchivePath != "blobs/0" {
		t.Fatalf("unexpected attachment contract: %+v", attachment)
	}
	blob := validated.blobs["blobs/0"]
	if blob.SizeBytes != 72 || blob.SHA256 != "2496a5beafe0cfdc8ce6af926ce081a1043db2d21b774b4733f3204ad768c4da" {
		t.Fatalf("unexpected blob contract: %+v", blob)
	}
	parsedOutput, err := json.Marshal(struct {
		Manifest nativeManifest             `json:"manifest"`
		Chat     map[string]json.RawMessage `json:"chat"`
	}{Manifest: validated.manifest, Chat: chat.payload.Raw})
	if err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []string{"local-1", "codeExecutionAccessToken", "syncUserId", "encryptionKey"} {
		if bytes.Contains(parsedOutput, []byte(excluded)) {
			t.Fatalf("parser output contains excluded local or secret field %q", excluded)
		}
	}
}

func TestNativeCloudContractFixtureProvenance(t *testing.T) {
	fixture, err := os.ReadFile("testdata/native-cloud-import-v1.zip")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(fixture)
	const webFixtureSHA256 = "3a4b8c93a983f3dcfaa0df6b4a4de21a86f49eb1a8babe3824f10468861deb10"
	if got := hex.EncodeToString(sum[:]); got != webFixtureSHA256 {
		t.Fatalf("web fixture drifted: got %s, update it from the documented source and review the parser contract", got)
	}
}

func TestNativePortableMessageFieldsRoundTrip(t *testing.T) {
	input := []byte(`{"title":"Portable","messages":[{"role":"assistant","content":"answer","turnId":"turn-1","modelDisplayName":"Open Model","documentContent":"document","multimodalText":"multimodal","thoughts":"reasoning","isThinking":false,"thinkingDuration":1.5,"isError":true,"isRateLimitError":false,"isHourlyRateLimitError":false,"webSearchBeforeThinking":true,"searchReasoning":"search","quote":"quote","attachments":[{"id":"document-1","type":"document","fileName":"scan.pdf","mimeType":"application/pdf","textContent":"text","description":"scan","fileSize":10,"pages":[{"page":1,"text":"page","is_scanned":true}]}],"documents":[{"name":"legacy.txt"}],"imageData":[{"base64":"aW1hZ2U=","mimeType":"image/png"}],"timestamp":"2026-08-20T12:00:00.000Z","urlFetches":[{"id":"fetch-1","url":"https://example.com","status":"completed"}],"webSearch":{"query":"query","status":"completed","sources":[{"title":"Source","url":"https://example.com"}],"reason":"evidence"},"annotations":[{"type":"url_citation","url_citation":{"title":"Source","url":"https://example.com","start_index":0,"end_index":6}}],"timeline":[{"type":"thinking","id":"thinking-1","content":"reasoning","isThinking":false,"duration":1.5},{"type":"tool_call","id":"tool-1","toolCallId":"call-1","name":"lookup","arguments":"{}","resolvedAt":1,"resolution":{"text":"ok","data":{"keep":true}}},{"type":"content","id":"content-1","content":"answer"},{"type":"code_exec","id":"code-1","calls":[{"id":"exec-1","toolName":"python","arguments":{"code":"print(1)"},"status":"completed","output":"1"}]}],"toolCalls":[{"id":"call-1","name":"lookup","arguments":"{}"}],"codeExecCalls":[{"id":"exec-1","toolName":"python","arguments":{"code":"print(1)"},"status":"completed","output":"1"}]}],"createdAt":"2026-08-20T12:00:00.000Z","updatedAt":"2026-08-20T12:00:01.000Z","isLocalOnly":false}`)
	archive := nativeTestArchive(t, "portable-message", []nativeTestEntity{{kind: "chat", sourceID: "chat-1", path: "entities/chat/0.json", payload: input}}, nil, nil)
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	arch := &importArchive{zr: zr, files: make(map[string]*zip.File)}
	if err := arch.validateAndIndex("tinfoil_backup"); err != nil {
		t.Fatal(err)
	}
	validated, err := validateNativeBackup(arch)
	if err != nil {
		t.Fatal(err)
	}
	chat := validated.chats[0].payload
	output, _, err := buildNativeChatPayload(context.Background(), Deps{}, Session{}, nil, nil, &ImportJobState{}, "chat-1", "", importer.RestoreMarker{}, chat)
	if err != nil {
		t.Fatal(err)
	}
	var source, restored map[string]any
	if err := json.Unmarshal(input, &source); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output, &restored); err != nil {
		t.Fatal(err)
	}
	sourceMessage := source["messages"].([]any)[0].(map[string]any)
	restoredMessage := restored["messages"].([]any)[0].(map[string]any)
	for _, field := range []string{"role", "content", "turnId", "modelDisplayName", "documentContent", "multimodalText", "thoughts", "isThinking", "thinkingDuration", "isError", "isRateLimitError", "isHourlyRateLimitError", "webSearchBeforeThinking", "searchReasoning", "quote", "attachments", "documents", "imageData", "timestamp", "urlFetches", "webSearch", "annotations", "timeline", "toolCalls", "codeExecCalls"} {
		if !reflect.DeepEqual(restoredMessage[field], sourceMessage[field]) {
			t.Fatalf("portable message field %s changed: got %#v, want %#v", field, restoredMessage[field], sourceMessage[field])
		}
	}
}

func TestNativeImportStatusFieldNamesMatchWebContract(t *testing.T) {
	response := ImportStatusResponse{
		Status: string(ImportJobCompleted), Phase: "complete", Imported: 3, Failed: 1, Total: 5,
		Counts:   map[string]ImportKindCounts{"project": {Imported: 1}, "document": {Imported: 1, Blocked: 1}, "chat": {Imported: 1, Failed: 1}},
		Warnings: []string{"attachment omitted"}, Errors: []string{"chat failed"},
		ProjectMappings: map[string]string{"source-project": "destination-project"}, JobID: "job-1",
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	if got, want := sortedMapKeys(value), []string{"counts", "errors", "failed", "imported", "job_id", "phase", "project_mappings", "status", "total", "warnings"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("status fields = %v, want %v", got, want)
	}
	var counts map[string]map[string]json.RawMessage
	if err := json.Unmarshal(value["counts"], &counts); err != nil {
		t.Fatal(err)
	}
	for kind, count := range counts {
		if got, want := sortedMapKeys(count), []string{"blocked", "failed", "imported", "skipped"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("%s count fields = %v, want %v", kind, got, want)
		}
	}
}

func sortedMapKeys[T any](value map[string]T) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func TestNativeMessageThinkingDurationRoundTrip(t *testing.T) {
	for _, value := range []string{"4", "4.25"} {
		t.Run(value, func(t *testing.T) {
			input := []byte(fmt.Sprintf(`{"title":"Chat","messages":[{"role":"assistant","content":"done","timestamp":"2026-08-18T12:00:00Z","thinkingDuration":%s}],"createdAt":"2026-08-18T12:00:00Z","isLocalOnly":false}`, value))
			var chat nativeChatPayload
			if err := decodeStrictJSON(input, &chat); err != nil {
				t.Fatal(err)
			}
			if got := chat.Messages[0].ThinkingDuration.String(); got != value {
				t.Fatalf("decoded thinking duration = %q, want %q", got, value)
			}

			output, _, err := buildNativeChatPayload(context.Background(), Deps{}, Session{}, nil, nil, nil, "chat-1", "", importer.RestoreMarker{}, chat)
			if err != nil {
				t.Fatal(err)
			}
			var restored struct {
				Messages []map[string]json.RawMessage `json:"messages"`
			}
			if err := json.Unmarshal(output, &restored); err != nil {
				t.Fatal(err)
			}
			if got := string(restored.Messages[0]["thinkingDuration"]); got != value {
				t.Fatalf("restored thinking duration = %q, want %q", got, value)
			}
		})
	}
}

func TestNativeMessageRejectsInvalidThinkingDurationTypes(t *testing.T) {
	for _, value := range []string{`"4"`, `true`, `{}`, `[]`, `null`} {
		t.Run(value, func(t *testing.T) {
			var message nativeMessagePayload
			if err := json.Unmarshal([]byte(fmt.Sprintf(`{"role":"assistant","content":"done","timestamp":"2026-08-18T12:00:00Z","thinkingDuration":%s}`, value)), &message); err == nil {
				t.Fatalf("expected thinking duration %s to be rejected", value)
			}
		})
	}
}

func TestNativeBackupValidatesChatTitle(t *testing.T) {
	tests := []struct {
		name      string
		titleJSON string
		wantTitle string
		wantValid bool
	}{
		{name: "null", titleJSON: `"title":null,`},
		{name: "missing"},
		{name: "wrong type", titleJSON: `"title":true,`},
		{name: "empty", titleJSON: `"title":"",`, wantValid: true},
		{name: "nonempty", titleJSON: `"title":"Chat",`, wantTitle: "Chat", wantValid: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(fmt.Sprintf(`{%s"messages":[],"createdAt":"2026-08-18T12:00:00Z","isLocalOnly":false}`, tc.titleJSON))
			archive := nativeTestArchive(t, "backup-title", []nativeTestEntity{
				{kind: "chat", sourceID: "c1", path: "entities/chat.json", payload: payload},
			}, nil, nil)
			zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
			if err != nil {
				t.Fatal(err)
			}
			arch := &importArchive{zr: zr, files: make(map[string]*zip.File)}
			if err := arch.validateAndIndex("tinfoil_backup"); err != nil {
				t.Fatal(err)
			}
			validated, err := validateNativeBackup(arch)
			if !tc.wantValid {
				if err == nil {
					t.Fatal("expected chat title validation failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("valid chat title was rejected: %v", err)
			}
			if got := validated.chats[0].payload.Title; got != tc.wantTitle {
				t.Fatalf("validated title = %q, want %q", got, tc.wantTitle)
			}
		})
	}
}

func TestNativeBackupValidatesEverythingBeforeWrites(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	archive := nativeTestArchive(t, "backup-invalid", []nativeTestEntity{
		{kind: "project", sourceID: "p1", path: "entities/project.json", payload: []byte(`{"name":"Valid","memory":[]}`)},
		{kind: "chat", sourceID: "c1", path: "entities/chat.json", payload: []byte(`{"title":"Local","messages":[],"createdAt":"2024-01-01T00:00:00.000Z","isLocalOnly":true}`)},
	}, nil, nil)
	job := stageArchive(t, f, "tinfoil_backup", archive)
	job.cek = append([]byte(nil), f.userKey...)
	if err := runImportJob(context.Background(), f.handler.deps, importSession(f), job); err == nil {
		t.Fatal("expected local-only chat validation failure")
	}
	if len(f.cp.blobs) != 0 {
		t.Fatalf("validation failure wrote %d blobs", len(f.cp.blobs))
	}
}

func TestValidJSONTimeRequiresRFC3339(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  json.RawMessage
		want bool
	}{
		{name: "null", raw: json.RawMessage(`null`), want: true},
		{name: "RFC3339", raw: json.RawMessage(`"2024-01-01T00:00:00Z"`), want: true},
		{name: "RFC3339Nano", raw: json.RawMessage(`"2024-01-01T00:00:00.123456789Z"`), want: true},
		{name: "malformed", raw: json.RawMessage(`"yesterday"`), want: false},
		{name: "empty", raw: json.RawMessage(`""`), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validJSONTime(tc.raw); got != tc.want {
				t.Fatalf("validJSONTime(%s) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestNativeBackupRejectsBinaryDocumentAttachment(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	archive := nativeTestArchive(t, "backup-document", []nativeTestEntity{
		{kind: "chat", sourceID: "c1", path: "entities/chat.json", payload: []byte(`{"title":"Document","messages":[{"role":"user","content":"read","timestamp":"2024-01-01T00:00:00Z","attachments":[{"type":"document","fileName":"brief.pdf","archivePath":"blobs/brief.pdf"}]}],"createdAt":"2024-01-01T00:00:00Z","isLocalOnly":false}`)},
	}, map[string][]byte{"blobs/brief.pdf": []byte("pdf")}, nil)
	job := stageArchive(t, f, "tinfoil_backup", archive)
	job.cek = append([]byte(nil), f.userKey...)

	if err := runImportJob(context.Background(), f.handler.deps, importSession(f), job); err == nil {
		t.Fatal("expected binary document attachment validation failure")
	}
	if len(f.cp.blobs) != 0 {
		t.Fatal("invalid archive must not write blobs")
	}
}

func TestNativeBackupRejectsManifestAndArchiveMismatches(t *testing.T) {
	entity := nativeTestEntity{kind: "project", sourceID: "p1", path: "entities/project.json", payload: []byte(`{"name":"Valid","memory":[]}`)}
	tests := []struct {
		name   string
		mutate func(*nativeManifest)
	}{
		{name: "version", mutate: func(m *nativeManifest) { m.Version++ }},
		{name: "count", mutate: func(m *nativeManifest) { m.Counts.Projects++ }},
		{name: "hash", mutate: func(m *nativeManifest) { m.Entities[0].SHA256 = hashOf([]byte("wrong")) }},
		{name: "path", mutate: func(m *nativeManifest) { m.Entities[0].Path = "../project.json" }},
		{name: "unlisted", mutate: func(m *nativeManifest) { m.Blobs = nil; m.Counts.Blobs = 0 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.cp.currentKID = f.userKeyID
			blobs := map[string][]byte(nil)
			if tc.name == "unlisted" {
				blobs = map[string][]byte{"extra.txt": []byte("unlisted")}
			}
			archive := nativeTestArchive(t, "backup-bad", []nativeTestEntity{entity}, blobs, func(m *nativeManifest) {
				if tc.mutate != nil {
					tc.mutate(m)
				}
			})
			job := stageArchive(t, f, "tinfoil_backup", archive)
			job.cek = append([]byte(nil), f.userKey...)
			if err := runImportJob(context.Background(), f.handler.deps, importSession(f), job); err == nil {
				t.Fatal("expected native backup validation failure")
			}
			if len(f.cp.blobs) != 0 {
				t.Fatal("invalid archive must not write blobs")
			}
		})
	}
}

func TestNativeBackupAdvancesCollisionsAndBlocksDependents(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	for generation := 0; generation < maxRestoreGenerations; generation++ {
		id := mappedRestoreID(f.userSub, "backup-blocked", "project", "p1", generation)
		f.cp.blobs["project/"+id] = &cpBlob{ETag: 1, KeyID: f.userKeyID, Body: []byte("foreign")}
	}
	archive := nativeTestArchive(t, "backup-blocked", []nativeTestEntity{
		{kind: "project", sourceID: "p1", path: "entities/project.json", payload: []byte(`{"name":"Blocked","memory":[]}`)},
		{kind: "document", sourceID: "d1", projectSourceID: "p1", path: "entities/document.json", payload: []byte(`{"filename":"doc.txt","contentType":"text/plain","sourceSizeBytes":1,"sizeBytes":1,"content":"x"}`)},
		{kind: "chat", sourceID: "c1", projectSourceID: "p1", path: "entities/chat.json", payload: []byte(`{"title":"Blocked","messages":[],"createdAt":"2024-01-01T00:00:00.000Z","isLocalOnly":false}`)},
	}, nil, nil)
	job := runNativeTestArchive(t, f, archive)
	snap := job.Snapshot()
	if snap.Counts["project"].Failed != 1 || snap.Counts["document"].Blocked != 1 || snap.Counts["chat"].Blocked != 1 {
		t.Fatalf("unexpected blocked dependency status: %+v", snap.Counts)
	}
}

func TestMappedRestoreIDsAreUserScoped(t *testing.T) {
	first := mappedRestoreID("user-a", "backup", "chat", "source", 0)
	if first == mappedRestoreID("user-b", "backup", "chat", "source", 0) {
		t.Fatal("different destination users must receive different ids")
	}
	if first == mappedRestoreID("user-a", "backup", "chat", "source", 1) {
		t.Fatal("different generations must receive different ids")
	}
}

func TestNativeBackupCleansAttachmentsAfterChatPushFailure(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	backupID := "backup-push-failure"
	chatID := mappedRestoreID(f.userSub, backupID, "chat", "c1", 0)
	f.cp.putBlobFailures["chat/"+chatID] = 100
	archive, image := nativeAttachmentTestArchive(t, backupID)

	job := runNativeTestArchive(t, f, archive)
	if job.Snapshot().Counts["chat"].Failed != 1 {
		t.Fatalf("expected failed chat: %+v", job.Snapshot())
	}
	attachmentID, _, err := deriveAttachmentMaterials(attachmentIdemKey(chatID, "blobs/image.png", 0), chatID, f.userSub, image)
	if err != nil {
		t.Fatal(err)
	}
	if _, indexed := f.cp.attachmentIndex[attachmentID]; indexed || f.bk.has(attachmentID) {
		t.Fatal("failed chat left a tentative attachment index or blob")
	}
}

func TestNativeBackupKeepsAttachmentsWhenChatPushResponseIsLost(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	backupID := "backup-lost-response"
	chatID := mappedRestoreID(f.userSub, backupID, "chat", "c1", 0)
	f.cp.postPutFailures["chat/"+chatID] = 1
	archive, image := nativeAttachmentTestArchive(t, backupID)

	job := runNativeTestArchive(t, f, archive)
	chatCounts := job.Snapshot().Counts["chat"]
	if chatCounts.Imported+chatCounts.Skipped != 1 {
		t.Fatalf("committed chat was not counted as restored: %+v", job.Snapshot())
	}
	attachmentID, _, err := deriveAttachmentMaterials(attachmentIdemKey(chatID, "blobs/image.png", 0), chatID, f.userSub, image)
	if err != nil {
		t.Fatal(err)
	}
	if f.cp.attachmentIndex[attachmentID] != chatID || !f.bk.has(attachmentID) {
		t.Fatal("lost push response removed attachments referenced by the committed chat")
	}
}

func TestNativeBackupRetainsBlobWhenAttachmentIndexCleanupFails(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	backupID := "backup-cleanup-failure"
	chatID := mappedRestoreID(f.userSub, backupID, "chat", "c1", 0)
	f.cp.putBlobFailures["chat/"+chatID] = 100
	archive, image := nativeAttachmentTestArchive(t, backupID)
	attachmentID, _, err := deriveAttachmentMaterials(attachmentIdemKey(chatID, "blobs/image.png", 0), chatID, f.userSub, image)
	if err != nil {
		t.Fatal(err)
	}
	f.cp.deleteAttachmentIndexFailures[attachmentID] = 1

	job := runNativeTestArchive(t, f, archive)
	if job.Snapshot().Counts["chat"].Failed != 1 {
		t.Fatalf("expected failed chat: %+v", job.Snapshot())
	}
	if f.cp.attachmentIndex[attachmentID] != chatID || !f.bk.has(attachmentID) {
		t.Fatal("cleanup failure removed a blob that may still be referenced")
	}
}

func TestNativeBackupCleansAttachmentsBeforeCollisionRetry(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	backupID := "backup-collision"
	firstChatID := mappedRestoreID(f.userSub, backupID, "chat", "c1", 0)
	secondChatID := mappedRestoreID(f.userSub, backupID, "chat", "c1", 1)
	f.cp.beforePutBlob = func(scope, id string) {
		if scope == "chat" && id == firstChatID {
			f.cp.blobs["chat/"+id] = &cpBlob{ETag: 1, KeyID: f.userKeyID, Body: []byte("foreign")}
			f.cp.beforePutBlob = nil
		}
	}
	archive, image := nativeAttachmentTestArchive(t, backupID)

	job := runNativeTestArchive(t, f, archive)
	if job.Snapshot().Counts["chat"].Imported != 1 || f.cp.blobs["chat/"+secondChatID] == nil {
		t.Fatalf("collision retry did not commit the next candidate: %+v", job.Snapshot())
	}
	firstAttachmentID, _, err := deriveAttachmentMaterials(attachmentIdemKey(firstChatID, "blobs/image.png", 0), firstChatID, f.userSub, image)
	if err != nil {
		t.Fatal(err)
	}
	secondAttachmentID, _, err := deriveAttachmentMaterials(attachmentIdemKey(secondChatID, "blobs/image.png", 0), secondChatID, f.userSub, image)
	if err != nil {
		t.Fatal(err)
	}
	if _, indexed := f.cp.attachmentIndex[firstAttachmentID]; indexed || f.bk.has(firstAttachmentID) {
		t.Fatal("colliding candidate left a tentative attachment index or blob")
	}
	if f.cp.attachmentIndex[secondAttachmentID] != secondChatID || !f.bk.has(secondAttachmentID) {
		t.Fatal("committed collision retry attachment was not preserved")
	}
}

func TestNativeProjectMappingsIncludeEveryAcceptedProject(t *testing.T) {
	job := &ImportJobState{}
	const projectCount = 10_001
	for index := 0; index < projectCount; index++ {
		job.setProjectMapping(fmt.Sprintf("source-%d", index), fmt.Sprintf("destination-%d", index))
	}
	if got := len(job.Snapshot().ProjectMappings); got != projectCount {
		t.Fatalf("project mapping count = %d, want %d", got, projectCount)
	}
}

func nativeAttachmentTestArchive(t *testing.T, backupID string) ([]byte, []byte) {
	t.Helper()
	image := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x42}, 64)...)
	archive := nativeTestArchive(t, backupID, []nativeTestEntity{
		{kind: "chat", sourceID: "c1", path: "entities/chat.json", payload: []byte(`{"title":"Image","messages":[{"role":"user","content":"look","timestamp":"2024-01-01T00:00:00.000Z","attachments":[{"type":"image","fileName":"image.png","mimeType":"image/png","fileSize":72,"archivePath":"blobs/image.png"}]}],"createdAt":"2024-01-01T00:00:00.000Z","isLocalOnly":false}`)},
	}, map[string][]byte{"blobs/image.png": image}, nil)
	return archive, image
}

func runNativeTestArchive(t *testing.T, f *fixture, archive []byte) *ImportJobState {
	t.Helper()
	job := stageArchive(t, f, "tinfoil_backup", archive)
	job.cek = append([]byte(nil), f.userKey...)
	if err := runImportJob(context.Background(), f.handler.deps, importSession(f), job); err != nil {
		t.Fatalf("run native import: %v", err)
	}
	return job
}

func nativeTestArchive(t *testing.T, backupID string, entities []nativeTestEntity, blobs map[string][]byte, mutate func(*nativeManifest)) []byte {
	t.Helper()
	manifest := nativeManifest{Format: nativeManifestFormat, Version: nativeManifestVersion, SourceBackupID: backupID, Counts: &nativeManifestCounts{}}
	entries := make(map[string][]byte)
	for _, entity := range entities {
		manifest.Entities = append(manifest.Entities, nativeEntityManifest{
			Kind: entity.kind, SourceID: entity.sourceID, ProjectSourceID: entity.projectSourceID,
			Path: entity.path, SHA256: hashOf(entity.payload), SizeBytes: int64(len(entity.payload)),
		})
		entries[entity.path] = entity.payload
		switch entity.kind {
		case "project":
			manifest.Counts.Projects++
		case "document":
			manifest.Counts.Documents++
		case "chat":
			manifest.Counts.Chats++
		}
	}
	for path, data := range blobs {
		manifest.Blobs = append(manifest.Blobs, nativeBlobManifest{Path: path, SHA256: hashOf(data), SizeBytes: int64(len(data))})
		entries[path] = data
		manifest.Counts.Blobs++
	}
	if mutate != nil {
		mutate(&manifest)
	}
	if manifest.Entities == nil {
		manifest.Entities = []nativeEntityManifest{}
	}
	if manifest.Blobs == nil {
		manifest.Blobs = []nativeBlobManifest{}
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	entries[nativeManifestPath] = manifestJSON
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for path, data := range entries {
		writeZipEntry(t, zw, path, data)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func decryptNativeTestBlob(t *testing.T, f *fixture, scope, id string) map[string]any {
	t.Helper()
	resp, err := Pull(context.Background(), f.handler.deps, importSession(f), PullRequest{
		Scope: scope, IDs: []string{id}, Keys: []PullKey{{Key: f.userKeyB64, KeyID: f.userKeyID}},
	})
	if err != nil || len(resp.Items) != 1 || !resp.Items[0].OK {
		t.Fatalf("pull restored blob: resp=%+v err=%v", resp, err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(resp.Items[0].Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}
