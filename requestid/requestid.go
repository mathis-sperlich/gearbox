// Package requestid threads a per-request correlation ID through the HTTP
// pipeline onto the context the engine sees. Wire FromContext into the Engine as
// its RequestIDFunc so a transition's audit row points back to the causing request.
package requestid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// HeaderName is the request/response header carrying the correlation ID.
const HeaderName = "X-Request-Id"

type contextKey struct{}

// FromContext returns the request ID on ctx, or "" if none. Its signature matches
// gearbox.RequestIDFunc, so pass it directly as the Engine's RequestID.
func FromContext(ctx context.Context) string {
	v, _ := ctx.Value(contextKey{}).(string)
	return v
}

// With attaches id to ctx, for background callers outside the HTTP middleware.
func With(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// Middleware honours an inbound X-Request-Id or generates a fresh one, puts it on
// the request context, and mirrors it on the response header. Mount outside the mux.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(HeaderName)
		if id == "" {
			id = newID()
		}
		w.Header().Set(HeaderName, id)
		next.ServeHTTP(w, r.WithContext(With(r.Context(), id)))
	})
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "" // crypto/rand failure: callers treat "" as "no ID".
	}
	return hex.EncodeToString(b[:])
}
