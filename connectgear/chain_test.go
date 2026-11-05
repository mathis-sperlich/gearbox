package connectgear_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/mathis-sperlich/gearbox"
	"github.com/mathis-sperlich/gearbox/authjwt"
	"github.com/mathis-sperlich/gearbox/connectgear"
)

const (
	chainSecret = "connectgear-chain-test-secret-000000"
	procEcho    = "/test.v1.TestService/Echo"
	procPublic  = "/test.v1.TestService/Public"
	procPanic   = "/test.v1.TestService/Panic"
	procStream  = "/test.v1.TestService/Stream"
	procSPanic  = "/test.v1.TestService/StreamPanic"
)

// seen records what the handlers observed.
type seen struct {
	mu    sync.Mutex
	calls int
	who   []gearbox.Principal
}

func (s *seen) hit(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.who = append(s.who, connectgear.PrincipalFrom(ctx))
}

func (s *seen) snapshot() (int, []gearbox.Principal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, append([]gearbox.Principal(nil), s.who...)
}

type str = wrapperspb.StringValue

// serve mounts unary and server-streaming handlers behind opts and returns
// the server's base URL.
func serve(t *testing.T, s *seen, opts connect.HandlerOption) string {
	t.Helper()
	unary := func(ctx context.Context, r *connect.Request[str]) (*connect.Response[str], error) {
		s.hit(ctx)
		return connect.NewResponse(wrapperspb.String(r.Msg.GetValue())), nil
	}
	stream := func(ctx context.Context, _ *connect.Request[str], out *connect.ServerStream[str]) error {
		s.hit(ctx)
		return out.Send(wrapperspb.String("one"))
	}
	mux := http.NewServeMux()
	mux.Handle(procEcho, connect.NewUnaryHandler(procEcho, unary, opts))
	mux.Handle(procPublic, connect.NewUnaryHandler(procPublic, unary, opts))
	mux.Handle(procPanic, connect.NewUnaryHandler(procPanic, func(context.Context, *connect.Request[str]) (*connect.Response[str], error) {
		panic(`pq: relation "secrets" does not exist`)
	}, opts))
	mux.Handle(procStream, connect.NewServerStreamHandler(procStream, stream, opts))
	mux.Handle(procSPanic, connect.NewServerStreamHandler(procSPanic, func(context.Context, *connect.Request[str], *connect.ServerStream[str]) error {
		panic("stream secret boom")
	}, opts))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func verifier(t *testing.T) *authjwt.Verifier {
	t.Helper()
	v, err := authjwt.NewVerifier(chainSecret)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func token(t *testing.T, v *authjwt.Verifier, ttl time.Duration, now time.Time) string {
	t.Helper()
	tok, _, err := v.Mint(authjwt.MintClaims{Subject: "user-1"}, ttl, now)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func call(t *testing.T, base, proc, bearer string) error {
	t.Helper()
	req := connect.NewRequest(wrapperspb.String("hi"))
	if bearer != "" {
		req.Header().Set("Authorization", "Bearer "+bearer)
	}
	_, err := connect.NewClient[str, str](http.DefaultClient, base+proc).CallUnary(context.Background(), req)
	return err
}

func callStream(t *testing.T, base, proc, bearer string) error {
	t.Helper()
	req := connect.NewRequest(wrapperspb.String("hi"))
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

func subjectOf(p gearbox.Principal) string {
	if c, ok := p.(*authjwt.Claims); ok {
		return c.Subject
	}
	return ""
}

func TestAuthInterceptor_UnaryAndStreamShareOneAuthPath(t *testing.T) {
	v := verifier(t)
	s := &seen{}
	base := serve(t, s, connectgear.Options(connectgear.AuthInterceptor(connectgear.Bearer(v))))
	now := time.Now()
	good := token(t, v, time.Hour, now)
	expired := token(t, v, time.Minute, now.Add(-time.Hour))
	forged := token(t, mustVerifier(t, "another-secret-another-secret-0000"), time.Hour, now)

	for name, do := range map[string]func(string) error{
		"unary":  func(b string) error { return call(t, base, procEcho, b) },
		"stream": func(b string) error { return callStream(t, base, procStream, b) },
	} {
		for _, bad := range []struct{ what, bearer string }{{"none", ""}, {"expired", expired}, {"forged", forged}, {"garbage", "x.y.z"}} {
			if err := do(bad.bearer); connect.CodeOf(err) != connect.CodeUnauthenticated {
				t.Errorf("%s, %s token: err = %v, want unauthenticated", name, bad.what, err)
			}
		}
		if err := do(good); err != nil {
			t.Fatalf("%s, valid token: %v", name, err)
		}
	}
	n, who := s.snapshot()
	if n != 2 || subjectOf(who[0]) != "user-1" || subjectOf(who[1]) != "user-1" {
		t.Fatalf("handler calls %d, principals %v; want 2 calls as user-1", n, who)
	}
}

func mustVerifier(t *testing.T, secret string) *authjwt.Verifier {
	t.Helper()
	v, err := authjwt.NewVerifier(secret)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Public procedures skip auth for unary calls only; a stream named public
// still needs credentials (fail closed).
func TestAuthInterceptor_PublicProceduresAreUnaryOnly(t *testing.T) {
	s := &seen{}
	authn := connectgear.Bearer(verifier(t))
	base := serve(t, s, connectgear.Options(connectgear.AuthInterceptor(authn, connectgear.PublicProcedures(procPublic, procStream))))
	if err := call(t, base, procPublic, ""); err != nil {
		t.Fatalf("public unary without credentials: %v", err)
	}
	if err := call(t, base, procEcho, ""); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("non-public unary without credentials: err = %v", err)
	}
	if err := callStream(t, base, procStream, ""); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("stream listed as public, no credentials: err = %v, want unauthenticated", err)
	}
	if n, who := s.snapshot(); n != 1 || who[0] != nil {
		t.Fatalf("handler calls %d, principals %v; want only the public call, anonymous", n, who)
	}
}

// The Authenticator sees the spec, and its errors are mapped: a Connect error
// passes as is, a gearbox sentinel through Err, anything else is internal with
// its text withheld; no principal and no error is a refusal.
func TestAuthInterceptor_AuthenticatorResults(t *testing.T) {
	var mu sync.Mutex
	var specs []connect.StreamType
	var result func() (gearbox.Principal, error)
	authn := func(_ context.Context, spec connect.Spec, _ http.Header) (gearbox.Principal, error) {
		mu.Lock()
		specs = append(specs, spec.StreamType)
		mu.Unlock()
		return result()
	}
	s := &seen{}
	base := serve(t, s, connectgear.Options(connectgear.AuthInterceptor(authn)))

	cases := []struct {
		name string
		res  func() (gearbox.Principal, error)
		want connect.Code
	}{
		{"connect error", func() (gearbox.Principal, error) {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("nope"))
		}, connect.CodePermissionDenied},
		{"sentinel", func() (gearbox.Principal, error) { return nil, gearbox.ErrUnauthenticated }, connect.CodeUnauthenticated},
		{"raw", func() (gearbox.Principal, error) { return nil, errors.New("select secret") }, connect.CodeInternal},
		{"nil nil", func() (gearbox.Principal, error) { return nil, nil }, connect.CodeUnauthenticated},
	}
	for _, c := range cases {
		result = c.res
		for kind, err := range map[string]error{"unary": call(t, base, procEcho, ""), "stream": callStream(t, base, procStream, "")} {
			if connect.CodeOf(err) != c.want {
				t.Errorf("%s/%s: err = %v, want %v", c.name, kind, err, c.want)
			}
			if err != nil && strings.Contains(err.Error(), "select secret") {
				t.Errorf("%s/%s: raw error reached the client: %v", c.name, kind, err)
			}
		}
	}
	if n, _ := s.snapshot(); n != 0 {
		t.Fatalf("handler ran %d times for refused calls", n)
	}

	result = func() (gearbox.Principal, error) { return "svc", nil }
	mu.Lock()
	specs = nil
	mu.Unlock()
	if err := callStream(t, base, procStream, ""); err != nil {
		t.Fatal(err)
	}
	if err := call(t, base, procEcho, ""); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(specs) != 2 || specs[0] != connect.StreamTypeServer || specs[1] != connect.StreamTypeUnary {
		t.Fatalf("authenticator saw stream types %v", specs)
	}
	if _, who := s.snapshot(); who[0] != gearbox.Principal("svc") || who[1] != gearbox.Principal("svc") {
		t.Fatalf("principals %v", who)
	}
}

// On a client the interceptor is inert: it neither authenticates nor
// strips anything.
func TestAuthInterceptor_PassesClientCallsThrough(t *testing.T) {
	called := false
	authn := func(context.Context, connect.Spec, http.Header) (gearbox.Principal, error) {
		called = true
		return nil, errors.New("must not run")
	}
	s := &seen{}
	base := serve(t, s, connectgear.Options())
	ic := connectgear.AuthInterceptor(authn)
	client := connect.NewClient[str, str](http.DefaultClient, base+procEcho, connect.WithInterceptors(ic))
	if _, err := client.CallUnary(context.Background(), connect.NewRequest(wrapperspb.String("x"))); err != nil {
		t.Fatal(err)
	}
	sc := connect.NewClient[str, str](http.DefaultClient, base+procStream, connect.WithInterceptors(ic))
	st, err := sc.CallServerStream(context.Background(), connect.NewRequest(wrapperspb.String("x")))
	if err != nil {
		t.Fatal(err)
	}
	for st.Receive() {
	}
	if err := st.Err(); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if called {
		t.Fatal("authenticator ran on a client call")
	}
}

// A panicking handler comes back as internal with the panic withheld, unary
// and stream alike, and the hook sees the value and stack.
func TestRecover_WithholdsThePanic(t *testing.T) {
	var mu sync.Mutex
	var got []string
	opts := connect.WithHandlerOptions(
		connect.WithInterceptors(connectgear.AuthInterceptor(func(context.Context, connect.Spec, http.Header) (gearbox.Principal, error) {
			return "u", nil
		})),
		connectgear.Recover(func(_ context.Context, spec connect.Spec, v any, stack []byte) {
			mu.Lock()
			defer mu.Unlock()
			if len(stack) == 0 {
				t.Error("empty stack")
			}
			got = append(got, spec.Procedure+" "+v.(string))
		}),
	)
	base := serve(t, &seen{}, opts)
	for name, err := range map[string]error{"unary": call(t, base, procPanic, ""), "stream": callStream(t, base, procSPanic, "")} {
		if connect.CodeOf(err) != connect.CodeInternal {
			t.Errorf("%s: err = %v, want internal", name, err)
		}
		if err != nil && (strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "relation")) {
			t.Errorf("%s: the panic reached the client: %v", name, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("hook calls %v", got)
	}
}

// Options caps what a handler reads: one byte over the limit is
// resource_exhausted before the handler runs.
func TestOptions_LimitsTheRequestSize(t *testing.T) {
	if connectgear.DefaultMaxRequestBytes != 8<<20 {
		t.Fatalf("DefaultMaxRequestBytes = %d", connectgear.DefaultMaxRequestBytes)
	}
	s := &seen{}
	base := serve(t, s, connectgear.Options(connectgear.AuthInterceptor(connectgear.Bearer(verifier(t)), connectgear.PublicProcedures(procPublic))))
	client := connect.NewClient[str, str](http.DefaultClient, base+procPublic)
	// A StringValue of n bytes encodes as n+tag+varint(n) bytes.
	big := strings.Repeat("a", connectgear.DefaultMaxRequestBytes)
	if _, err := client.CallUnary(context.Background(), connect.NewRequest(wrapperspb.String(big))); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("over-size: err = %v, want resource_exhausted", err)
	}
	if n, _ := s.snapshot(); n != 0 {
		t.Fatalf("handler ran %d times for an over-size request", n)
	}
	if _, err := client.CallUnary(context.Background(), connect.NewRequest(wrapperspb.String(big[:1024]))); err != nil {
		t.Fatalf("small request: %v", err)
	}
}
