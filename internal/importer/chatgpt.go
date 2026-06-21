package importer

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type chatgptConversation struct {
	ID             string                 `json:"id"`
	ConversationID string                 `json:"conversation_id"`
	Title          string                 `json:"title"`
	CreateTime     float64                `json:"create_time"`
	UpdateTime     float64                `json:"update_time"`
	Mapping        map[string]chatgptNode `json:"mapping"`
}

type chatgptNode struct {
	ID       string          `json:"id"`
	Message  *chatgptMessage `json:"message"`
	Parent   string          `json:"parent"`
	Children []string        `json:"children"`
}

type chatgptMessage struct {
	Author     chatgptAuthor   `json:"author"`
	Content    chatgptContent  `json:"content"`
	CreateTime float64         `json:"create_time"`
	Metadata   chatgptMetadata `json:"metadata"`
}

type chatgptAuthor struct {
	Role string `json:"role"`
}

type chatgptContent struct {
	ContentType string            `json:"content_type"`
	Parts       []json.RawMessage `json:"parts"`
	Thoughts    []chatgptThought  `json:"thoughts"`
}

type chatgptThought struct {
	Content string `json:"content"`
	Summary string `json:"summary"`
}

type chatgptMetadata struct {
	FinishedDurationSec float64             `json:"finished_duration_sec"`
	Attachments         []chatgptAttachment `json:"attachments"`
}

type chatgptAttachment struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	MimeType string `json:"mime_type"`
}

type chatgptAssetPointer struct {
	ContentType  string `json:"content_type"`
	AssetPointer string `json:"asset_pointer"`
}

func parseChatGPT(data []byte, opts Options, emit EmitFunc) (Result, error) {
	var conversations []chatgptConversation
	if err := json.Unmarshal(data, &conversations); err != nil {
		return Result{}, fmt.Errorf("importer: parse chatgpt conversations: %w", err)
	}

	var result Result
	for ci := range conversations {
		conv := &conversations[ci]
		chat := buildChatGPTChat(conv, opts)
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

func buildChatGPTChat(conv *chatgptConversation, opts Options) *Chat {
	nodeMap := conv.Mapping
	visited := make(map[string]struct{}, len(nodeMap))
	var messages []Message

	var process func(nodeID string)
	process = func(nodeID string) {
		if _, ok := visited[nodeID]; ok {
			return
		}
		visited[nodeID] = struct{}{}
		node, ok := nodeMap[nodeID]
		if !ok {
			return
		}
		if msg := node.Message; msg != nil && chatgptIsRenderable(msg) {
			if m, ok := buildChatGPTMessage(nodeID, nodeMap, conv, opts); ok {
				messages = append(messages, m)
			}
		}
		for _, childID := range node.Children {
			process(childID)
		}
	}

	for nodeID, node := range nodeMap {
		if node.Parent == "" || node.Parent == "client-created-root" {
			process(nodeID)
		}
	}

	if len(messages) == 0 {
		return nil
	}

	createdAt := unixSeconds(conv.CreateTime)
	stableKey := conv.ID
	if stableKey == "" {
		stableKey = conv.ConversationID
	}
	if stableKey == "" {
		stableKey = "chatgpt:" + conv.Title + ":" + createdAt.UTC().Format(time.RFC3339Nano)
	}
	title := conv.Title
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

func chatgptIsRenderable(msg *chatgptMessage) bool {
	role := msg.Author.Role
	if role != "user" && role != "assistant" {
		return false
	}
	ct := msg.Content.ContentType
	if ct != "text" && ct != "multimodal_text" {
		return false
	}
	return len(msg.Content.Parts) > 0
}

func buildChatGPTMessage(nodeID string, nodeMap map[string]chatgptNode, conv *chatgptConversation, opts Options) (Message, bool) {
	node := nodeMap[nodeID]
	msg := node.Message

	text, pointers := chatgptParts(msg.Content.Parts)
	content := strings.TrimSpace(text)

	attachments := chatgptAttachments(msg, pointers, opts.Index)
	if content == "" && len(attachments) == 0 {
		return Message{}, false
	}

	timestamp := unixSeconds(conv.CreateTime)
	if msg.CreateTime != 0 {
		timestamp = unixSeconds(msg.CreateTime)
	}

	out := Message{
		Role:        msg.Author.Role,
		Content:     content,
		Attachments: attachments,
		Timestamp:   jsTime{timestamp},
	}

	if msg.Author.Role == "assistant" {
		thoughts, dur := chatgptThoughtsInChain(nodeID, nodeMap)
		out.Thoughts = thoughts
		out.ThinkingDuration = dur
	}
	return out, true
}

// chatgptParts splits the mixed parts array into the joined text and the
// asset pointers referencing binary media (images, DALL-E output).
func chatgptParts(parts []json.RawMessage) (string, []chatgptAssetPointer) {
	var texts []string
	var pointers []chatgptAssetPointer
	for _, raw := range parts {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			texts = append(texts, s)
			continue
		}
		var ptr chatgptAssetPointer
		if err := json.Unmarshal(raw, &ptr); err == nil && ptr.AssetPointer != "" {
			pointers = append(pointers, ptr)
		}
	}
	return strings.Join(texts, "\n"), pointers
}

func chatgptAttachments(msg *chatgptMessage, pointers []chatgptAssetPointer, idx *Index) []Attachment {
	var out []Attachment
	seen := make(map[string]struct{})

	add := func(att Attachment, key string) {
		if key != "" {
			if _, ok := seen[key]; ok {
				return
			}
			seen[key] = struct{}{}
		}
		out = append(out, att)
	}

	for _, a := range msg.Metadata.Attachments {
		id := trimFileID(a.ID)
		att := Attachment{
			Type:     AttachmentDocument,
			FileName: a.Name,
			MimeType: a.MimeType,
		}
		if idx != nil {
			if name, ok := idx.ByIDPrefix(id); ok {
				if isImageRef(a.MimeType, name) {
					att.Type = AttachmentImage
				}
				att.BinaryRef = name
				if att.FileName == "" {
					att.FileName = basename(name)
				}
				if att.MimeType == "" {
					att.MimeType = mimeFromExtension(name)
				}
			}
		}
		add(att, id)
	}

	for _, ptr := range pointers {
		id := trimFileID(ptr.AssetPointer)
		if idx == nil {
			continue
		}
		name, ok := idx.ByIDPrefix(id)
		if !ok {
			continue
		}
		att := Attachment{
			Type:      AttachmentImage,
			FileName:  basename(name),
			MimeType:  mimeFromExtension(name),
			BinaryRef: name,
		}
		add(att, id)
	}

	return out
}

func chatgptThoughtsInChain(nodeID string, nodeMap map[string]chatgptNode) (string, int) {
	visited := make(map[string]struct{})
	var thoughts string
	var duration int
	cur := nodeID
	for cur != "" {
		if _, ok := visited[cur]; ok {
			break
		}
		visited[cur] = struct{}{}
		node, ok := nodeMap[cur]
		if !ok {
			break
		}
		if msg := node.Message; msg != nil {
			switch msg.Content.ContentType {
			case "thoughts":
				var texts []string
				for _, t := range msg.Content.Thoughts {
					if t.Content != "" {
						texts = append(texts, t.Content)
					} else if t.Summary != "" {
						texts = append(texts, t.Summary)
					}
				}
				if len(texts) > 0 && thoughts == "" {
					thoughts = strings.Join(texts, "\n\n")
				}
			case "reasoning_recap":
				if duration == 0 && msg.Metadata.FinishedDurationSec > 0 {
					duration = int(msg.Metadata.FinishedDurationSec)
				}
			}
		}
		cur = node.Parent
	}
	return thoughts, duration
}

func unixSeconds(sec float64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	whole := int64(sec)
	nanos := int64((sec - float64(whole)) * 1e9)
	return time.Unix(whole, nanos).UTC()
}
