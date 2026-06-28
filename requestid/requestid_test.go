package requestid_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mathis-sperlich/gearbox/requestid"
)

func TestRequestID_MiddlewareGeneratesAndPropagates(t *testing.T) {
	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = requestid.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := requestid.Middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	header := rec.Header().Get(requestid.HeaderName)
	if header == "" {
		t.Fatal("response is missing the X-Request-Id header")
	}
	if seen == "" {
		t.Fatal("FromContext inside the handler returned empty")
	}
	if seen != header {
		t.Fatalf("context id %q != response header id %q", seen, header)
	}
}

func TestRequestID_MiddlewarePreservesInboundID(t *testing.T) {
	const inbound = "inbound-correlation-id"
	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = requestid.FromContext(r.Context())
	})
	h := requestid.Middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(requestid.HeaderName, inbound)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if seen != inbound {
		t.Fatalf("FromContext = %q, want preserved inbound id %q", seen, inbound)
	}
	if got := rec.Header().Get(requestid.HeaderName); got != inbound {
		t.Fatalf("response header = %q, want preserved inbound id %q", got, inbound)
	}
}

func TestRequestID_WithFromContextRoundtrip(t *testing.T) {
	const id = "manual-id"
	ctx := requestid.With(context.Background(), id)
	if got := requestid.FromContext(ctx); got != id {
		t.Fatalf("FromContext = %q, want %q", got, id)
	}
	// A bare context carries no id.
	if got := requestid.FromContext(context.Background()); got != "" {
		t.Fatalf("FromContext of bare context = %q, want empty", got)
	}
}
