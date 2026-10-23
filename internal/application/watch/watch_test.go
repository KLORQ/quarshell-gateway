package watch

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeSource struct {
	name   string
	events []Event
	err    error
	wait   <-chan struct{}
	index  int
}

func (f *fakeSource) Name() string { return f.name }

func (f *fakeSource) Next(ctx context.Context) (Event, bool, error) {
	if f.wait != nil {
		select {
		case <-f.wait:
		case <-ctx.Done():
			return Event{}, false, ctx.Err()
		}
	}
	if f.index < len(f.events) {
		event := f.events[f.index]
		f.index++
		return event, true, nil
	}
	if f.err != nil {
		return Event{}, false, f.err
	}
	return Event{}, false, nil
}

func collect(t *testing.T, events <-chan Event, timeout time.Duration) []Event {
	t.Helper()
	var result []Event
	deadline := time.After(timeout)
	for {
		select {
		case event, open := <-events:
			if !open {
				return result
			}
			result = append(result, event)
		case <-deadline:
			t.Fatalf("timed out waiting for events")
		}
	}
}

func TestCombinedSourcesCloseIndependently(t *testing.T) {
	first := &fakeSource{name: "first", events: []Event{{Payload: []byte("a")}, {Payload: []byte("b")}}}
	second := &fakeSource{name: "second", events: []Event{{Payload: []byte("c")}}}
	events, errs := Run(context.Background(), []Source{first, second}, Options{})
	collected := collect(t, events, time.Second)
	counts := map[string]int{}
	closed := map[string]int{}
	for _, event := range collected {
		if event.Closed {
			closed[event.Source]++
			continue
		}
		counts[event.Source]++
	}
	if counts["first"] != 2 || counts["second"] != 1 {
		t.Fatalf("counts = %v", counts)
	}
	if closed["first"] != 1 || closed["second"] != 1 {
		t.Fatalf("closed = %v", closed)
	}
	if _, open := <-errs; open {
		t.Fatalf("unexpected error")
	}
}

func TestClosedSourceDoesNotEndWatch(t *testing.T) {
	release := make(chan struct{})
	first := &fakeSource{name: "first"}
	second := &fakeSource{name: "second", wait: release, events: []Event{{Payload: []byte("late")}}}
	events, _ := Run(context.Background(), []Source{first, second}, Options{})
	deadline := time.After(time.Second)
	seenClosed := false
	for !seenClosed {
		select {
		case event := <-events:
			if event.Source == "first" && event.Closed {
				seenClosed = true
			}
		case <-deadline:
			t.Fatalf("first source did not close")
		}
	}
	close(release)
	select {
	case event := <-events:
		if event.Source != "second" || string(event.Payload) != "late" {
			t.Fatalf("second source event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatalf("second source was ended by the first closure")
	}
}

func TestSourceErrorDoesNotStopOthers(t *testing.T) {
	first := &fakeSource{name: "first", err: errors.New("boom")}
	second := &fakeSource{name: "second", events: []Event{{Payload: []byte("ok")}}}
	events, errs := Run(context.Background(), []Source{first, second}, Options{})
	var sawEvent bool
	var sawError bool
	for !sawEvent || !sawError {
		select {
		case event, open := <-events:
			if open && event.Source == "second" && !event.Closed {
				sawEvent = true
			}
		case err, open := <-errs:
			if open && err != nil {
				sawError = true
			}
		case <-time.After(time.Second):
			t.Fatalf("event=%v error=%v", sawEvent, sawError)
		}
	}
}

func TestContextCancellationClosesWatch(t *testing.T) {
	block := make(chan struct{})
	source := &fakeSource{name: "blocked", wait: block}
	ctx, cancel := context.WithCancel(context.Background())
	events, _ := Run(ctx, []Source{source}, Options{})
	cancel()
	select {
	case _, open := <-events:
		if open {
			// Drain any closed event if it raced the cancellation.
			for range events {
			}
		}
	case <-time.After(time.Second):
		t.Fatalf("watch did not close on cancellation")
	}
}
