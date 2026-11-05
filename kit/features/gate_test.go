package features_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/mathis-sperlich/gearbox"
	"github.com/mathis-sperlich/gearbox/authjwt"
	"github.com/mathis-sperlich/gearbox/connectgear"
	"github.com/mathis-sperlich/gearbox/kit/features"
)

const (
	gateSecret  = "features-gate-test-secret-0000000000"
	procSend    = "/test.v1.Sheets/Send"   // gated on FLAG_SHEETS
	procOpen    = "/test.v1.Sheets/Open"   // ungated
	procWatch   = "/test.v1.Sheets/Watch"  // gated server stream
	procPublic  = "/test.v1.Sheets/Public" // ungated, no credentials needed
	procOpenStr = "/test.v1.Sheets/Tail"   // ungated server stream
)

type str = wrapperspb.StringValue

// scopeOf reads the scope off the request: the StringValue is the scope.
func scopeOf(_ context.Context, _ string, msg any) (string, bool) {
	m, ok := msg.(*str)
	if !ok || m.GetValue() == "" {
		return "", false
	}
	return m.GetValue(), true
}

func gate(t *testing.T, cfg features.GateConfig[flag]) *features.Gate[flag] {
	t.Helper()
	if cfg.Registry == nil {
		cfg.Registry = registry(t)
	}
	if cfg.Methods == nil {
		cfg.Methods = map[string]flag{procSend: flagSheets, procWatch: flagSheets}
	}
	g, err := features.NewGate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func tenanted(t *testing.T) *features.Gate[flag] {
	return gate(t, features.GateConfig[flag]{ScopeOf: scopeOf, Canonical: features.UUIDScope})
}

// hasLog records what Has said in each handler call.
type hasLog struct {
	mu  sync.Mutex
	has []bool
}

func (h *hasLog) add(v bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.has = append(h.has, v)
}

func (h *hasLog) get() []bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]bool(nil), h.has...)
}

func serve(t *testing.T, authn connectgear.Authenticator, g *features.Gate[flag], log *hasLog) string {
	t.Helper()
	opts := connectgear.Options(
		connectgear.AuthInterceptor(authn, connectgear.PublicProcedures(procPublic)),
		g.Interceptor(),
	)
	unary := func(ctx context.Context, r *connect.Request[str]) (*connect.Response[str], error) {
		log.add(features.Has(ctx, flagSheets))
		return connect.NewResponse(wrapperspb.String("ok")), nil
	}
	stream := func(ctx context.Context, r *connect.Request[str], out *connect.ServerStream[str]) error {
		log.add(features.Has(g.WithScope(ctx, r.Msg.GetValue()), flagSheets))
		return out.Send(wrapperspb.String("ok"))
	}
	mux := http.NewServeMux()
	for _, p := range []string{procSend, procOpen, procPublic} {
		mux.Handle(p, connect.NewUnaryHandler(p, unary, opts))
	}
	for _, p := range []string{procWatch, procOpenStr} {
		mux.Handle(p, connect.NewServerStreamHandler(p, stream, opts))
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func mint(t *testing.T, v *authjwt.Verifier, buckets map[string]map[string]bool) string {
	t.Helper()
	tok, _, err := v.Mint(authjwt.MintClaims{Subject: "user-1", Extra: claim(buckets)}, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func call(base, proc, bearer, scope string) error {
	req := connect.NewRequest(wrapperspb.String(scope))
	if bearer != "" {
		req.Header().Set("Authorization", "Bearer "+bearer)
	}
	_, err := connect.NewClient[str, str](http.DefaultClient, base+proc).CallUnary(context.Background(), req)
	return err
}

func callStream(base, proc, bearer, scope string) error {
	req := connect.NewRequest(wrapperspb.String(scope))
	if bearer != "" {
		req.Header().Set("Authorization", "Bearer "+bearer)
	}
	st, err := connect.NewClient[str, str](http.DefaultClient, base+proc).CallServerStream(context.Background(), req)
	if err != nil {
		return err
	}
	defer st.Close()
	for st.Receive() {
	}
	return st.Err()
}

func denied(t *testing.T, what string, err error) {
	t.Helper()
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("%s: err = %v, want permission_denied", what, err)
	}
}

func TestNewGate_RefusesUnknownFeatures(t *testing.T) {
	for _, f := range []flag{flagUnspecified, flag(99)} {
		_, err := features.NewGate(features.GateConfig[flag]{
			Registry: registry(t),
			Methods:  map[string]flag{procSend: f},
		})
		if err == nil {
			t.Errorf("gate on %v accepted", f)
		}
	}
	if _, err := features.NewGate(features.GateConfig[flag]{}); err == nil {
		t.Error("gate without a registry accepted")
	}
}

func TestGate_UnaryFailsClosed(t *testing.T) {
	v := mustVerifier(t)
	g := tenanted(t)
	log := &hasLog{}
	base := serve(t, connectgear.Bearer(v), g, log)

	none := mint(t, v, nil)
	orgOn := mint(t, v, map[string]map[string]bool{orgA: {"FLAG_SHEETS": true}})
	orgOffGlobalOn := mint(t, v, map[string]map[string]bool{orgA: {"FLAG_SHEETS": false}, features.GlobalBucket: {"FLAG_SHEETS": true}})
	globalOn := mint(t, v, map[string]map[string]bool{features.GlobalBucket: {"FLAG_SHEETS": true}})
	globalKill := mint(t, v, map[string]map[string]bool{features.GlobalBucket: {"FLAG_SHEETS": false}})
	elsewhere := mint(t, v, map[string]map[string]bool{orgB: {"FLAG_SHEETS": true}})

	if err := call(base, procOpen, none, ""); err != nil {
		t.Fatalf("ungated, no decisions, no scope: %v", err)
	}
	if err := call(base, procPublic, "", ""); err != nil {
		t.Fatalf("ungated public, unauthenticated: %v", err)
	}
	denied(t, "gated, no decisions", call(base, procSend, none, orgA))
	denied(t, "gated, no scope", call(base, procSend, orgOn, ""))
	denied(t, "gated, junk scope", call(base, procSend, globalOn, "not-a-uuid"))
	denied(t, "gated, scope '*' with a global grant", call(base, procSend, globalOn, features.GlobalBucket))
	denied(t, "gated, global kill", call(base, procSend, globalKill, orgA))
	denied(t, "gated, another scope's grant", call(base, procSend, elsewhere, orgA))
	for _, spelling := range []string{"AAAAAAAA-1111-1111-1111-111111111111", "{" + orgA + "}", "urn:uuid:" + orgA} {
		denied(t, "gated, scope denial + global grant, spelled "+spelling, call(base, procSend, orgOffGlobalOn, spelling))
	}

	if err := call(base, procSend, orgOn, orgA); err != nil {
		t.Fatalf("gated, scope grant: %v", err)
	}
	if err := call(base, procSend, orgOn, "AAAAAAAA-1111-1111-1111-111111111111"); err != nil {
		t.Fatalf("gated, scope grant, upper-case scope: %v", err)
	}
	if err := call(base, procSend, globalOn, orgB); err != nil {
		t.Fatalf("gated, global grant: %v", err)
	}
	// Has inside ungated handlers reflects the caller's scope too.
	if err := call(base, procOpen, orgOn, orgB); err != nil {
		t.Fatal(err)
	}
	if err := call(base, procOpen, orgOn, orgA); err != nil {
		t.Fatal(err)
	}
	if err := call(base, procPublic, "", orgA); err != nil {
		t.Fatal(err)
	}
	want := []bool{false, false, true, true, true, false, true, false}
	if got := log.get(); len(got) != len(want) || !equal(got, want) {
		t.Fatalf("Has per handler call = %v, want %v", got, want)
	}
}

func equal(a, b []bool) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return len(a) == len(b)
}

// A principal that isn't *authjwt.Claims carries no decisions: gated calls
// are refused, ungated ones pass.
func TestGate_ForeignPrincipalHasNoDecisions(t *testing.T) {
	authn := func(context.Context, connect.Spec, http.Header) (gearbox.Principal, error) {
		return "api-key-42", nil
	}
	log := &hasLog{}
	base := serve(t, authn, tenanted(t), log)
	denied(t, "gated, foreign principal", call(base, procSend, "", orgA))
	denied(t, "gated stream, foreign principal", callStream(base, procWatch, "", orgA))
	if err := call(base, procOpen, "", orgA); err != nil {
		t.Fatal(err)
	}
	if got := log.get(); !equal(got, []bool{false}) {
		t.Fatalf("Has = %v", got)
	}
}

func TestGate_ServerStreamGatedOnItsRequest(t *testing.T) {
	v := mustVerifier(t)
	log := &hasLog{}
	base := serve(t, connectgear.Bearer(v), tenanted(t), log)
	orgOn := mint(t, v, map[string]map[string]bool{orgA: {"FLAG_SHEETS": true}})

	denied(t, "stream, no decisions", callStream(base, procWatch, mint(t, v, nil), orgA))
	denied(t, "stream, other scope", callStream(base, procWatch, orgOn, orgB))
	denied(t, "stream, no scope", callStream(base, procWatch, orgOn, ""))
	if err := callStream(base, procWatch, orgOn, orgA); err != nil {
		t.Fatalf("stream, scope grant: %v", err)
	}
	if err := callStream(base, procOpenStr, orgOn, orgB); err != nil {
		t.Fatalf("ungated stream: %v", err)
	}
	if got := log.get(); !equal(got, []bool{true, false}) {
		t.Fatalf("Has in stream handlers = %v, want [true false]", got)
	}
}

// Without ScopeOf the app doesn't tenant: the global bucket decides.
func TestGate_Untenanted(t *testing.T) {
	v := mustVerifier(t)
	log := &hasLog{}
	base := serve(t, connectgear.Bearer(v), gate(t, features.GateConfig[flag]{}), log)
	denied(t, "no decision", call(base, procSend, mint(t, v, nil), ""))
	denied(t, "scope grant only", call(base, procSend, mint(t, v, map[string]map[string]bool{orgA: {"FLAG_SHEETS": true}}), orgA))
	if err := call(base, procSend, mint(t, v, map[string]map[string]bool{features.GlobalBucket: {"FLAG_SHEETS": true}}), ""); err != nil {
		t.Fatalf("global grant: %v", err)
	}
	if got := log.get(); !equal(got, []bool{true}) {
		t.Fatalf("Has = %v", got)
	}
}

func TestGate_RefuseHook(t *testing.T) {
	v := mustVerifier(t)
	var gotScope string
	var gotFeature flag
	g := gate(t, features.GateConfig[flag]{
		ScopeOf:   scopeOf,
		Canonical: features.UUIDScope,
		Refuse: func(_ context.Context, _ string, f flag, scope string) *connect.Error {
			gotFeature, gotScope = f, scope
			return connect.NewError(connect.CodeFailedPrecondition, errors.New("FEATURE_NOT_ENABLED"))
		},
	})
	base := serve(t, connectgear.Bearer(v), g, &hasLog{})
	err := call(base, procSend, mint(t, v, nil), "AAAAAAAA-1111-1111-1111-111111111111")
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("err = %v, want the hook's error", err)
	}
	if gotFeature != flagSheets || gotScope != orgA {
		t.Fatalf("hook saw %v %q", gotFeature, gotScope)
	}
	// The hook is only for "resolved off"; a missing scope is still refused plainly.
	denied(t, "no scope", call(base, procSend, mint(t, v, nil), ""))
}

func mustVerifier(t *testing.T) *authjwt.Verifier {
	t.Helper()
	v, err := authjwt.NewVerifier(gateSecret)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// fakeConn is a handler stream whose Receive yields the queued scopes and
// whose Send records.
type fakeConn struct {
	connect.StreamingHandlerConn
	procedure string
	in        []string
	sent      int
}

func (f *fakeConn) Spec() connect.Spec {
	return connect.Spec{Procedure: f.procedure, StreamType: connect.StreamTypeBidi}
}

func (f *fakeConn) Receive(msg any) error {
	if len(f.in) == 0 {
		return errors.New("EOF")
	}
	msg.(*str).Value, f.in = f.in[0], f.in[1:]
	return nil
}

func (f *fakeConn) Send(any) error { f.sent++; return nil }

// A bidi handler that sends before it receives, or after a refused message,
// gets PermissionDenied; one whose message passed may send.
func TestGate_BidiSendWaitsForACheckedMessage(t *testing.T) {
	g := tenanted(t)
	ctx := connectgear.WithPrincipal(context.Background(), &authjwt.Claims{
		Subject: "u",
		Raw:     claim(map[string]map[string]bool{orgA: {"FLAG_SHEETS": true}}),
	})
	run := func(ctx context.Context, proc string, in []string, body func(connect.StreamingHandlerConn) error) (*fakeConn, error) {
		fc := &fakeConn{procedure: proc, in: in}
		err := g.Interceptor().WrapStreamingHandler(func(_ context.Context, c connect.StreamingHandlerConn) error {
			return body(c)
		})(ctx, fc)
		return fc, err
	}

	fc, err := run(ctx, procWatch, []string{orgA}, func(c connect.StreamingHandlerConn) error { return c.Send(&str{}) })
	denied(t, "send before receive", err)
	if fc.sent != 0 {
		t.Fatal("message leaked before any check")
	}

	fc, _ = run(ctx, procWatch, []string{orgA, orgB}, func(c connect.StreamingHandlerConn) error {
		if err := c.Receive(&str{}); err != nil {
			return err
		}
		if err := c.Send(&str{}); err != nil {
			return err
		}
		denied(t, "second message, other scope", c.Receive(&str{}))
		denied(t, "send after a refused message", c.Send(&str{}))
		return nil
	})
	if fc.sent != 1 {
		t.Fatalf("sent %d, want 1", fc.sent)
	}

	fc, err = run(ctx, procOpenStr, nil, func(c connect.StreamingHandlerConn) error { return c.Send(&str{}) })
	if err != nil || fc.sent != 1 {
		t.Fatalf("ungated stream send: %v, sent %d", err, fc.sent)
	}

	called := false
	_, err = run(context.Background(), procWatch, []string{orgA}, func(connect.StreamingHandlerConn) error { called = true; return nil })
	denied(t, "gated stream, unauthenticated", err)
	if called {
		t.Fatal("handler ran for an unauthenticated gated stream")
	}
}
