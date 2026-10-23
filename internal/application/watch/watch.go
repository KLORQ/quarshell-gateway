// Package watch combines independent event sources without coupling their
// lifecycles. A closed or failed source does not end the combined watch.
package watch

import (
	"context"
	"sync"

	"github.com/KLORQ/quarshell-core/domain"
)

// Event is one normalized event with its source and opaque cursor.
type Event struct {
	Source  string
	Cursor  string
	Payload []byte
	Closed  bool
}

// Source is one independently closing event stream.
type Source interface {
	Name() string
	Next(context.Context) (Event, bool, error)
}

// Options bounds the combined watch.
type Options struct {
	Buffer int
}

// Run merges sources. Each source closure emits a Closed event; the combined
// channel closes only after every source has closed or the context is canceled.
// Source errors are reported on the error channel and stop only that source.
func Run(ctx context.Context, sources []Source, options Options) (<-chan Event, <-chan error) {
	buffer := options.Buffer
	if buffer <= 0 {
		buffer = 64
	}
	events := make(chan Event, buffer)
	errors := make(chan error, len(sources)+1)
	if len(sources) == 0 {
		close(events)
		close(errors)
		return events, errors
	}
	var wait sync.WaitGroup
	wait.Add(len(sources))
	for _, source := range sources {
		go func(source Source) {
			defer wait.Done()
			name := source.Name()
			for {
				event, open, err := source.Next(ctx)
				if err != nil {
					select {
					case errors <- domain.Wrap(err, "watch.source", "source "+name+" failed"):
					default:
					}
					return
				}
				if !open {
					event = Event{Source: name, Closed: true}
				} else {
					event.Source = name
				}
				select {
				case events <- event:
				case <-ctx.Done():
					return
				}
				if !open {
					return
				}
			}
		}(source)
	}
	go func() {
		wait.Wait()
		close(events)
		close(errors)
	}()
	return events, errors
}
