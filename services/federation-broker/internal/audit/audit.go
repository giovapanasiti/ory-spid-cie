// Package audit emits structured security audit events. Events are always
// logged as JSON and, when configured, shipped asynchronously to the audit
// service. Events must never contain tokens, assertions or unnecessary PII.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Event is the canonical audit record (shared contract with audit-service).
type Event struct {
	ID            string         `json:"id"`
	Timestamp     time.Time      `json:"timestamp"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Actor         string         `json:"actor,omitempty"`
	Type          string         `json:"type"`
	Outcome       string         `json:"outcome"` // success | failure
	Service       string         `json:"service"`
	Context       map[string]any `json:"context,omitempty"`
}

// Sink ships events.
type Sink struct {
	URL   string
	Token string
	Log   *slog.Logger
	ch    chan Event
	hc    *http.Client
}

// New creates a sink with a bounded queue.
func New(url, token string, log *slog.Logger) *Sink {
	s := &Sink{URL: url, Token: token, Log: log, ch: make(chan Event, 1024), hc: &http.Client{Timeout: 5 * time.Second}}
	go s.loop()
	return s
}

// Emit records an event (non-blocking; drops with an error log when full).
func (s *Sink) Emit(ctx context.Context, typ, outcome, actor string, c map[string]any) {
	ev := Event{ID: uuid.NewString(), Timestamp: time.Now().UTC(), CorrelationID: CorrelationID(ctx), Actor: actor,
		Type: typ, Outcome: outcome, Service: "federation-broker", Context: c}
	s.Log.Info("audit", "audit_event", ev)
	if s.URL == "" {
		return
	}
	select {
	case s.ch <- ev:
	default:
		s.Log.Error("audit queue full, event not shipped", "event_id", ev.ID)
	}
}

func (s *Sink) loop() {
	for ev := range s.ch {
		body, _ := json.Marshal(ev)
		for attempt := 0; attempt < 3; attempt++ {
			req, _ := http.NewRequest(http.MethodPost, s.URL, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if s.Token != "" {
				req.Header.Set("Authorization", "Bearer "+s.Token)
			}
			resp, err := s.hc.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode < 300 {
					break
				}
			}
			if attempt == 2 {
				s.Log.Error("audit event delivery failed", "event_id", ev.ID)
			}
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
		}
	}
}

type ctxKey struct{}

// WithCorrelationID stores a correlation id in the context.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// CorrelationID returns the correlation id from the context.
func CorrelationID(ctx context.Context) string {
	v, _ := ctx.Value(ctxKey{}).(string)
	return v
}
