package inference

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

type embeddingServiceFunc func(context.Context, openai.EmbeddingNewParams, ...option.RequestOption) (*openai.CreateEmbeddingResponse, error)

func (f embeddingServiceFunc) New(ctx context.Context, params openai.EmbeddingNewParams, opts ...option.RequestOption) (*openai.CreateEmbeddingResponse, error) {
	return f(ctx, params, opts...)
}

func testClient(service embeddingService) *Client {
	return &Client{model: "test-model", embeddings: service}
}

func TestEmbedReturnsVectorsInInputOrder(t *testing.T) {
	c := testClient(embeddingServiceFunc(func(_ context.Context, params openai.EmbeddingNewParams, _ ...option.RequestOption) (*openai.CreateEmbeddingResponse, error) {
		if params.Model != "test-model" {
			t.Errorf("unexpected model %q", params.Model)
		}
		if got := params.Input.OfArrayOfStrings; !reflect.DeepEqual(got, []string{"a", "b"}) {
			t.Errorf("unexpected inputs %v", got)
		}
		if params.EncodingFormat != openai.EmbeddingNewParamsEncodingFormatFloat {
			t.Errorf("unexpected encoding format %q", params.EncodingFormat)
		}
		return &openai.CreateEmbeddingResponse{
			Data: []openai.Embedding{
				{Index: 1, Embedding: []float64{3, 4}},
				{Index: 0, Embedding: []float64{1, 2}},
			},
		}, nil
	}))
	got, err := c.Embed(context.Background(), []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]float32{{1, 2}, {3, 4}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Embed = %v, want %v", got, want)
	}
}

func TestEmbedRejectsBadResponses(t *testing.T) {
	cases := map[string][]openai.Embedding{
		"count mismatch":  {{Index: 0, Embedding: []float64{1}}},
		"index range":     {{Index: 0, Embedding: []float64{1}}, {Index: 5, Embedding: []float64{1}}},
		"duplicate index": {{Index: 0, Embedding: []float64{1}}, {Index: 0, Embedding: []float64{1}}},
		"empty vector":    {{Index: 0, Embedding: []float64{1}}, {Index: 1}},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			c := testClient(embeddingServiceFunc(func(context.Context, openai.EmbeddingNewParams, ...option.RequestOption) (*openai.CreateEmbeddingResponse, error) {
				return &openai.CreateEmbeddingResponse{Data: data}, nil
			}))
			if _, err := c.Embed(context.Background(), []string{"a", "b"}); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestEmbedDoesNotLeakUpstreamErrors(t *testing.T) {
	c := testClient(embeddingServiceFunc(func(context.Context, openai.EmbeddingNewParams, ...option.RequestOption) (*openai.CreateEmbeddingResponse, error) {
		return nil, errors.New("plaintext echo")
	}))
	if _, err := c.Embed(context.Background(), []string{"a"}); err == nil {
		t.Fatal("expected error")
	} else if strings.Contains(err.Error(), "plaintext echo") {
		t.Fatalf("upstream body leaked into error: %v", err)
	}
}

func TestEmbedRejectsNilResponse(t *testing.T) {
	c := testClient(embeddingServiceFunc(func(context.Context, openai.EmbeddingNewParams, ...option.RequestOption) (*openai.CreateEmbeddingResponse, error) {
		return nil, nil
	}))
	if _, err := c.Embed(context.Background(), []string{"a"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestConfigured(t *testing.T) {
	c, err := NewClient("", "m")
	if err != nil {
		t.Fatal(err)
	}
	if c.Configured() {
		t.Fatal("empty api key should not be configured")
	}
	c, err = NewClient("k", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Configured() {
		t.Fatal("empty model should not be configured")
	}
	if !testClient(embeddingServiceFunc(nil)).Configured() {
		t.Fatal("expected configured client")
	}
}

func TestProductionClientUsesTinfoilSDK(t *testing.T) {
	source, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if strings.Contains(text, `"net/http"`) || strings.Contains(text, "http.Client") {
		t.Fatal("production inference client must not use a plain HTTP client")
	}
	if !strings.Contains(text, "tinfoil.NewClientWithOptions") {
		t.Fatal("production inference client must use the attested Tinfoil SDK")
	}
}
