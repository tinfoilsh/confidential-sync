package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type nativeTestEntity struct {
	kind            string
	sourceID        string
	projectSourceID string
	path            string
	payload         []byte
}

type nativeContractFixture struct {
	SourceBackupID string `json:"source_backup_id"`
	Entities       []struct {
		Kind            string          `json:"kind"`
		SourceID        string          `json:"source_id"`
		ProjectSourceID string          `json:"project_source_id"`
		Payload         json.RawMessage `json:"payload"`
	} `json:"entities"`
	Blobs []struct {
		Path   string `json:"path"`
		Base64 string `json:"base64"`
	} `json:"blobs"`
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
	fixtureBytes, err := os.ReadFile("testdata/native-cloud-import-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture nativeContractFixture
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	entities := make([]nativeTestEntity, 0, len(fixture.Entities))
	for index, entity := range fixture.Entities {
		entities = append(entities, nativeTestEntity{
			kind: entity.Kind, sourceID: entity.SourceID, projectSourceID: entity.ProjectSourceID,
			path: fmt.Sprintf("entities/%s/%d.json", entity.Kind, index), payload: entity.Payload,
		})
	}
	blobs := make(map[string][]byte, len(fixture.Blobs))
	for _, blob := range fixture.Blobs {
		data, err := base64.StdEncoding.DecodeString(blob.Base64)
		if err != nil {
			t.Fatal(err)
		}
		blobs[blob.Path] = data
	}
	archive := nativeTestArchive(t, fixture.SourceBackupID, entities, blobs, nil)
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
		t.Fatalf("web contract fixture failed validation: %v", err)
	}
	if len(validated.projects) != 1 || len(validated.documents) != 1 || len(validated.chats) != 1 || len(validated.blobs) != 1 {
		t.Fatalf("unexpected validated fixture: %+v", validated)
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

func TestNativeProjectMappingsAreBounded(t *testing.T) {
	job := &ImportJobState{}
	for index := 0; index <= MaxImportProjectMappings; index++ {
		job.setProjectMapping(fmt.Sprintf("source-%d", index), fmt.Sprintf("destination-%d", index))
	}
	if got := len(job.Snapshot().ProjectMappings); got != MaxImportProjectMappings {
		t.Fatalf("project mapping count = %d, want %d", got, MaxImportProjectMappings)
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
