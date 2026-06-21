package importer

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Tinfoil's own export is Claude-compatible conversation JSON enriched
// with Tinfoil attachment metadata, so re-importing a Tinfoil export
// preserves attachments. Binary attachments are resolved through the
// index using their exportPath; documents carry inline textContent.

type tinfoilConversation struct {
	UUID         string           `json:"uuid"`
	Name         string           `json:"name"`
	CreatedAt    string           `json:"created_at"`
	UpdatedAt    string           `json:"updated_at"`
	ProjectID    string           `json:"projectId"`
	ChatMessages []tinfoilMessage `json:"chat_messages"`
}

type tinfoilMessage struct {
	Text        string              `json:"text"`
	Sender      string              `json:"sender"`
	CreatedAt   string              `json:"created_at"`
	Content     []claudeContent     `json:"content"`
	Attachments []tinfoilAttachment `json:"attachments"`
}

type tinfoilAttachment struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	FileName    string `json:"fileName"`
	MimeType    string `json:"mimeType"`
	FileSize    int64  `json:"fileSize"`
	ExportPath  string `json:"exportPath"`
	TextContent string `json:"textContent"`
}

func parseTinfoil(data []byte, opts Options, emit EmitFunc) (Result, error) {
	var conversations []tinfoilConversation
	if err := json.Unmarshal(data, &conversations); err != nil {
		return Result{}, fmt.Errorf("importer: parse tinfoil conversations: %w", err)
	}

	var result Result
	for ci := range conversations {
		conv := &conversations[ci]
		chat := buildTinfoilChat(conv, opts)
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

func buildTinfoilChat(conv *tinfoilConversation, opts Options) *Chat {
	var messages []Message
	for mi := range conv.ChatMessages {
		msg := &conv.ChatMessages[mi]
		text := strings.TrimSpace(msg.Text)
		attachments := tinfoilAttachments(msg, opts.Index)
		if text == "" && len(attachments) == 0 {
			continue
		}
		role, ok := claudeRole(msg.Sender)
		if !ok {
			continue
		}
		out := Message{
			Role:        role,
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
		stableKey = "tinfoil:" + conv.Name + ":" + conv.CreatedAt
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
		ProjectID:   conv.ProjectID,
		StableKey:   stableKey,
	}
}

func tinfoilAttachments(msg *tinfoilMessage, idx *Index) []Attachment {
	var out []Attachment
	for _, a := range msg.Attachments {
		if a.Type == string(AttachmentDocument) || a.TextContent != "" {
			out = append(out, Attachment{
				Type:        AttachmentDocument,
				FileName:    a.FileName,
				MimeType:    a.MimeType,
				TextContent: a.TextContent,
				FileSize:    a.FileSize,
			})
			continue
		}
		att := Attachment{
			Type:     AttachmentImage,
			FileName: a.FileName,
			MimeType: a.MimeType,
			FileSize: a.FileSize,
		}
		if idx != nil && a.ExportPath != "" {
			if name, ok := idx.Exact(a.ExportPath); ok {
				att.BinaryRef = name
				if att.FileName == "" {
					att.FileName = basename(name)
				}
			}
		}
		out = append(out, att)
	}
	return out
}
