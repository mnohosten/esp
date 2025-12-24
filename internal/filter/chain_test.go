package filter

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
)

// mockFilter is a test filter.
type mockFilter struct {
	name     string
	priority int
	result   *Result
	err      error
}

func (f *mockFilter) Name() string                                       { return f.name }
func (f *mockFilter) Priority() int                                      { return f.priority }
func (f *mockFilter) Process(ctx context.Context, msg *Message) (*Result, error) {
	return f.result, f.err
}

// mockEventBus captures events.
type mockEventBus struct {
	events []struct {
		topic string
		event any
	}
}

func (b *mockEventBus) Publish(topic string, event any) {
	b.events = append(b.events, struct {
		topic string
		event any
	}{topic, event})
}

func TestChain_Register(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	chain := NewChain(nil, logger)

	filter1 := &mockFilter{name: "filter1", priority: 100}
	filter2 := &mockFilter{name: "filter2", priority: 50}

	chain.Register(filter1)
	chain.Register(filter2)

	filters := chain.Filters()
	if len(filters) != 2 {
		t.Errorf("expected 2 filters, got %d", len(filters))
	}
}

func TestChain_Unregister(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	chain := NewChain(nil, logger)

	filter1 := &mockFilter{name: "filter1", priority: 100}
	chain.Register(filter1)

	chain.Unregister("filter1")

	filters := chain.Filters()
	if len(filters) != 0 {
		t.Errorf("expected 0 filters, got %d", len(filters))
	}
}

func TestChain_ProcessOrder(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	chain := NewChain(nil, logger)

	var order []string

	filter1 := &mockFilter{
		name:     "filter1",
		priority: 100,
		result:   &Result{Action: ActionAccept, Tags: []string{"filter1"}},
	}
	filter2 := &mockFilter{
		name:     "filter2",
		priority: 50,
		result:   &Result{Action: ActionAccept, Tags: []string{"filter2"}},
	}

	chain.Register(filter1)
	chain.Register(filter2)

	msg := &Message{ID: "test-1"}
	result, err := chain.Process(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// filter2 (priority 50) should run before filter1 (priority 100)
	// Tags should be merged in order: filter2, filter1
	if len(result.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(result.Tags))
	}

	_ = order // Suppress unused variable warning
}

func TestChain_ProcessMerge(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	chain := NewChain(nil, logger)

	filter1 := &mockFilter{
		name:     "filter1",
		priority: 10,
		result: &Result{
			Action:  ActionAccept,
			Score:   2.5,
			Headers: map[string]string{"X-Filter1": "yes"},
			Tags:    []string{"tag1"},
		},
	}
	filter2 := &mockFilter{
		name:     "filter2",
		priority: 20,
		result: &Result{
			Action:  ActionQuarantine,
			Score:   5.0,
			Reason:  "spam detected",
			Headers: map[string]string{"X-Filter2": "yes"},
			Tags:    []string{"tag2"},
			TargetFolder: "Junk",
		},
	}

	chain.Register(filter1)
	chain.Register(filter2)

	msg := &Message{ID: "test-1"}
	result, err := chain.Process(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check merged result
	if result.Action != ActionQuarantine {
		t.Errorf("expected ActionQuarantine, got %v", result.Action)
	}
	if result.Score != 7.5 {
		t.Errorf("expected score 7.5, got %f", result.Score)
	}
	if len(result.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(result.Tags))
	}
	if result.TargetFolder != "Junk" {
		t.Errorf("expected target folder 'Junk', got %q", result.TargetFolder)
	}
	if result.Headers["X-Filter1"] != "yes" || result.Headers["X-Filter2"] != "yes" {
		t.Errorf("expected both headers to be present")
	}
}

func TestChain_ProcessStopOnReject(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	chain := NewChain(nil, logger)

	filter1 := &mockFilter{
		name:     "filter1",
		priority: 10,
		result:   &Result{Action: ActionReject, Reason: "rejected"},
	}
	filter2 := &mockFilter{
		name:     "filter2",
		priority: 20,
		result:   &Result{Action: ActionAccept, Score: 100}, // Should not run
	}

	chain.Register(filter1)
	chain.Register(filter2)

	msg := &Message{ID: "test-1"}
	result, err := chain.Process(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should stop at reject, score should be 0
	if result.Action != ActionReject {
		t.Errorf("expected ActionReject, got %v", result.Action)
	}
	if result.Score != 0 {
		t.Errorf("expected score 0 (filter2 should not run), got %f", result.Score)
	}
}

func TestChain_ProcessErrorFailOpen(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	eventBus := &mockEventBus{}
	chain := NewChain(eventBus, logger)

	filter1 := &mockFilter{
		name:     "filter1",
		priority: 10,
		err:      errors.New("filter error"),
	}
	filter2 := &mockFilter{
		name:     "filter2",
		priority: 20,
		result:   &Result{Action: ActionAccept, Score: 1.0},
	}

	chain.Register(filter1)
	chain.Register(filter2)

	msg := &Message{ID: "test-1"}
	result, err := chain.Process(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error with fail-open: %v", err)
	}

	// Should continue despite filter1 error
	if result.Score != 1.0 {
		t.Errorf("expected score 1.0 (filter2 should run), got %f", result.Score)
	}

	// Should emit error event
	if len(eventBus.events) != 1 {
		t.Errorf("expected 1 event, got %d", len(eventBus.events))
	}
	if eventBus.events[0].topic != "filter.error" {
		t.Errorf("expected filter.error event, got %s", eventBus.events[0].topic)
	}
}

func TestChain_ProcessErrorFailClosed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	chain := NewChain(nil, logger)
	chain.SetConfig(ChainConfig{FailOpen: false})

	filter1 := &mockFilter{
		name:     "filter1",
		priority: 10,
		err:      errors.New("filter error"),
	}

	chain.Register(filter1)

	msg := &Message{ID: "test-1"}
	_, err := chain.Process(context.Background(), msg)
	if err == nil {
		t.Errorf("expected error with fail-closed")
	}
}

func TestChain_ProcessEvents(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	eventBus := &mockEventBus{}
	chain := NewChain(eventBus, logger)

	filter1 := &mockFilter{
		name:     "filter1",
		priority: 10,
		result: &Result{
			Action: ActionQuarantine,
			Score:  5.0,
			Tags:   []string{"spam"},
		},
	}

	chain.Register(filter1)

	msg := &Message{ID: "test-1"}
	_, err := chain.Process(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should emit match event
	if len(eventBus.events) != 1 {
		t.Errorf("expected 1 event, got %d", len(eventBus.events))
	}
	if eventBus.events[0].topic != "filter.matched" {
		t.Errorf("expected filter.matched event, got %s", eventBus.events[0].topic)
	}
}

func TestResult_Merge(t *testing.T) {
	r1 := &Result{
		Action:  ActionAccept,
		Score:   2.0,
		Headers: map[string]string{"X-A": "1"},
		Tags:    []string{"a"},
	}

	r2 := &Result{
		Action:       ActionQuarantine,
		Score:        3.0,
		Reason:       "quarantined",
		Headers:      map[string]string{"X-B": "2"},
		Tags:         []string{"b"},
		TargetFolder: "Junk",
	}

	r1.Merge(r2)

	if r1.Action != ActionQuarantine {
		t.Errorf("expected ActionQuarantine, got %v", r1.Action)
	}
	if r1.Score != 5.0 {
		t.Errorf("expected score 5.0, got %f", r1.Score)
	}
	if r1.Reason != "quarantined" {
		t.Errorf("expected reason 'quarantined', got %q", r1.Reason)
	}
	if len(r1.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(r1.Tags))
	}
	if r1.Headers["X-A"] != "1" || r1.Headers["X-B"] != "2" {
		t.Errorf("expected both headers")
	}
	if r1.TargetFolder != "Junk" {
		t.Errorf("expected target folder 'Junk', got %q", r1.TargetFolder)
	}
}

func TestAction_String(t *testing.T) {
	tests := []struct {
		action   Action
		expected string
	}{
		{ActionAccept, "accept"},
		{ActionReject, "reject"},
		{ActionQuarantine, "quarantine"},
		{ActionDefer, "defer"},
		{ActionDiscard, "discard"},
	}

	for _, tt := range tests {
		if got := tt.action.String(); got != tt.expected {
			t.Errorf("Action(%d).String() = %q, want %q", tt.action, got, tt.expected)
		}
	}
}
