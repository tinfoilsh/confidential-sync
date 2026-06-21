package importer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type claudeConversation struct {
	UUID         string          `json:"uuid"`
	Name         string          `json:"name"`
	CreatedAt    string          `json:"created_at"`
	UpdatedAt    string          `json:"updated_at"`
	ChatMessages []claudeMessage `json:"chat_messages"`
}

type claudeMessage struct {
	UUID        string             `json:"uuid"`
	Text        string             `json:"text"`
	Sender      string             `json:"sender"`
	CreatedAt   string             `json:"created_at"`
	Content     []claudeContent    `json:"content"`
	Attachments []claudeAttachment `json:"attachments"`
	Files       []claudeFile       `json:"files"`
	FilesV2     []claudeFile       `json:"files_v2"`
}

type claudeContent struct {
	Type           string `json:"type"`
	Thinking       string `json:"thinking"`
	StartTimestamp string `json:"start_timestamp"`
	StopTimestamp  string `json:"stop_timestamp"`
}

type claudeAttachment struct {
	FileName         string `json:"file_name"`
	FileSize         int64  `json:"file_size"`
	ExtractedContent string `json:"extracted_content"`
}

type claudeFile struct {
	FileName string `json:"file_name"`
	FileUUID string `json:"file_uuid"`
	FileKind string `json:"file_kind"`
}

func parseClaude(data []byte, opts Options, emit EmitFunc) (Result, error) {
	var conversations []claudeConversation
	if err := json.Unmarshal(data, &conversations); err != nil {
		return Result{}, fmt.Errorf("importer: parse claude conversations: %w", err)
	}

	var result Result
	for ci := range conversations {
		conv := &conversations[ci]
		chat := buildClaudeChat(conv, opts)
		if chat == nil {
			continue
		}
		result.Conversations++
		result.Messages += len(chat.Messages)
		for _, m := range chat.Messages {
			result.Attachments += len(m.Attachments)
		}
		if err := emit(chat); err != nil {
			return result, err
		}
	}
	return result, nil
}

func buildClaudeChat(conv *claudeConversation, opts Options) *Chat {
	var messages []Message
	for mi := range conv.ChatMessages {
		msg := &conv.ChatMessages[mi]
		text := strings.TrimSpace(msg.Text)
		attachments := claudeAttachments(msg, opts.Index)
		if text == "" && len(attachments) == 0 {
			continue
		}

		out := Message{
			Role:        claudeRole(msg.Sender),
			Content:     text,
			Attachments: attachments,
			Timestamp:   jsTime{parseISOTime(msg.CreatedAt)},
		}
		if msg.Sender == "assistant" {
			out.Thoughts, out.ThinkingDuration = claudeThinking(msg.Content)
		}
		messages = append(messages, out)
	}

	if len(messages) == 0 {
		return nil
	}

	createdAt := parseISOTime(conv.CreatedAt)
	stableKey := conv.UUID
	if stableKey == "" {
		stableKey = "claude:" + conv.Name + ":" + conv.CreatedAt
	}
	title := conv.Name
	if title == "" {
		title = "Imported Chat"
	}
	return &Chat{
		ID:          opts.id(stableKey, createdAt),
		Title:       title,
		Messages:    messages,
		CreatedAt:   jsTime{createdAt},
		IsLocalOnly: false,
		StableKey:   stableKey,
	}
}

func claudeRole(sender string) string {
	if sender == "human" {
		return "user"
	}
	return "assistant"
}

func claudeAttachments(msg *claudeMessage, idx *Index) []Attachment {
	var out []Attachment

	for _, a := range msg.Attachments {
		if a.ExtractedContent == "" {
			continue
		}
		out = append(out, Attachment{
			Type:        AttachmentDocument,
			FileName:    a.FileName,
			TextContent: a.ExtractedContent,
			FileSize:    a.FileSize,
		})
	}

	files := append([]claudeFile{}, msg.Files...)
	files = append(files, msg.FilesV2...)
	seen := make(map[string]struct{})
	for _, f := range files {
		key := f.FileUUID
		if key == "" {
			key = f.FileName
		}
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if idx == nil {
			continue
		}
		name, ok := idx.Exact(f.FileName)
		if !ok && f.FileUUID != "" {
			name, ok = idx.ByIDPrefix(f.FileUUID)
		}
		if !ok {
			continue
		}
		if !isImageRef("", name) {
			continue
		}
		out = append(out, Attachment{
			Type:      AttachmentImage,
			FileName:  basename(name),
			MimeType:  mimeFromExtension(name),
			BinaryRef: name,
		})
	}

	return out
}

func claudeThinking(content []claudeContent) (string, int) {
	var thoughts []string
	var stamps []time.Time
	for _, c := range content {
		if c.Type != "thinking" || c.Thinking == "" {
			continue
		}
		thoughts = append(thoughts, c.Thinking)
		if t := parseISOTime(c.StartTimestamp); !t.IsZero() {
			stamps = append(stamps, t)
		}
		if t := parseISOTime(c.StopTimestamp); !t.IsZero() {
			stamps = append(stamps, t)
		}
	}
	if len(thoughts) == 0 {
		return "", 0
	}
	duration := 0
	if len(stamps) >= 2 {
		sort.Slice(stamps, func(i, j int) bool { return stamps[i].Before(stamps[j]) })
		d := stamps[len(stamps)-1].Sub(stamps[0]).Seconds()
		duration = int(d + 0.5)
	}
	return strings.Join(thoughts, "\n\n"), duration
}

func parseISOTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000000Z07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
