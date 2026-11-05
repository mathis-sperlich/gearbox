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

func verifier(t *testing.T, secret string) *authjwt.Verifier {
	t.Helper()
	v, err := authjwt.NewVerifier(secret)
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

// callKinds runs one call per kind of handler, unary and server stream, so a
// test checks that both take the same path.
func callKinds(t *testing.T, base string) map[string]func(bearer string) error {
	return map[string]func(string) error{
		"unary":  func(bearer string) error { return call(t, base, procEcho, bearer) },
		"stream": func(bearer string) error { return callStream(t, base, procStream, bearer) },
	}
}

func TestAuthInterceptor_ValidTokenReachesHandlerAsPrincipal(t *testing.T) {
	// Given handlers behind bearer auth and a valid token for user-1
	v := verifier(t, chainSecret)
	handlers := &seen{}
	base := serve(t, handlers, connectgear.Options(connectgear.AuthInterceptor(connectgear.Bearer(v))))
	validToken := token(t, v, time.Hour, time.Now())
	for kind, callWith := range callKinds(t, base) {
		// When a unary call and a stream are made with it
		if err := callWith(validToken); err != nil {
			t.Fatalf("%s, valid token: %v", kind, err)
		}
	}
	// Then both handlers ran as user-1
	n, principals := handlers.snapshot()
	if n != 2 || subjectOf(principals[0]) != "user-1" || subjectOf(principals[1]) != "user-1" {
		t.Fatalf("handler calls %d, principals %v; want 2 calls as user-1", n, principals)
	}
}

func TestAuthInterceptor_PublicProceduresAreUnaryOnly(t *testing.T) {
	// Given a public unary procedure and a stream wrongly listed as public
	handlers := &seen{}
	authn := connectgear.Bearer(verifier(t, chainSecret))
	base := serve(t, handlers, connectgear.Options(connectgear.AuthInterceptor(authn, connectgear.PublicProcedures(procPublic, procStream))))
	// When each is called without credentials
	publicErr := call(t, base, procPublic, "")
	privateErr := call(t, base, procEcho, "")
	streamErr := callStream(t, base, procStream, "")
	// Then only the public unary call runs, anonymously; the stream fails closed
	if publicErr != nil {
		t.Fatalf("public unary without credentials: %v", publicErr)
	}
	if connect.CodeOf(privateErr) != connect.CodeUnauthenticated {
		t.Fatalf("non-public unary without credentials: err = %v", privateErr)
	}
	if connect.CodeOf(streamErr) != connect.CodeUnauthenticated {
		t.Fatalf("stream listed as public, no credentials: err = %v, want unauthenticated", streamErr)
	}
	if n, principals := handlers.snapshot(); n != 1 || principals[0] != nil {
		t.Fatalf("handler calls %d, principals %v; want only the public call, anonymous", n, principals)
	}
}

func TestAuthInterceptor_AuthenticatorSeesStreamType(t *testing.T) {
	// Given an Authenticator that records the stream type and admits "svc"
	var mu sync.Mutex
	var streamTypes []connect.StreamType
	recordingAuthn := func(_ context.Context, spec connect.Spec, _ http.Header) (gearbox.Principal, error) {
		mu.Lock()
		defer mu.Unlock()
		streamTypes = append(streamTypes, spec.StreamType)
		return "svc", nil
	}
	handlers := &seen{}
	base := serve(t, handlers, connectgear.Options(connectgear.AuthInterceptor(recordingAuthn)))
	// When a stream and then a unary call are made
	if err := callStream(t, base, procStream, ""); err != nil {
		t.Fatal(err)
	}
	if err := call(t, base, procEcho, ""); err != nil {
		t.Fatal(err)
	}
	// Then the Authenticator saw each stream type and the handlers ran as svc
	mu.Lock()
	defer mu.Unlock()
	if len(streamTypes) != 2 || streamTypes[0] != connect.StreamTypeServer || streamTypes[1] != connect.StreamTypeUnary {
		t.Fatalf("authenticator saw stream types %v", streamTypes)
	}
	if _, principals := handlers.snapshot(); principals[0] != gearbox.Principal("svc") || principals[1] != gearbox.Principal("svc") {
		t.Fatalf("principals %v", principals)
	}
}

func TestAuthInterceptor_PassesClientCallsThrough(t *testing.T) {
	// Given the auth interceptor on a client, with an Authenticator that must not run
	authnRan := false
	refusingAuthn := func(context.Context, connect.Spec, http.Header) (gearbox.Principal, error) {
		authnRan = true
		return nil, errors.New("must not run")
	}
	base := serve(t, &seen{}, connectgear.Options())
	clientInterceptor := connect.WithInterceptors(connectgear.AuthInterceptor(refusingAuthn))
	// When the client makes a unary call and a stream
	unaryClient := connect.NewClient[str, str](http.DefaultClient, base+procEcho, clientInterceptor)
	_, unaryErr := unaryClient.CallUnary(context.Background(), connect.NewRequest(wrapperspb.String("x")))
	streamClient := connect.NewClient[str, str](http.DefaultClient, base+procStream, clientInterceptor)
	stream, err := streamClient.CallServerStream(context.Background(), connect.NewRequest(wrapperspb.String("x")))
	if err != nil {
		t.Fatal(err)
	}
	for stream.Receive() {
	}
	_ = stream.Close()
	// Then both go through and the Authenticator never ran
	if unaryErr != nil || stream.Err() != nil {
		t.Fatalf("unary err = %v, stream err = %v", unaryErr, stream.Err())
	}
	if authnRan {
		t.Fatal("authenticator ran on a client call")
	}
}

func TestAuthInterceptor_RefusesBadTokens(t *testing.T) {
	// Given handlers behind bearer auth and tokens it must refuse
	v := verifier(t, chainSecret)
	handlers := &seen{}
	base := serve(t, handlers, connectgear.Options(connectgear.AuthInterceptor(connectgear.Bearer(v))))
	now := time.Now()
	badTokens := map[string]string{
		"none":    "",
		"expired": token(t, v, time.Minute, now.Add(-time.Hour)),
		"forged":  token(t, verifier(t, "another-secret-another-secret-0000"), time.Hour, now),
		"garbage": "x.y.z",
	}
	for kind, callWith := range callKinds(t, base) {
		for name, badToken := range badTokens {
			// When a call is made with it
			err := callWith(badToken)
			// Then it is unauthenticated
			if connect.CodeOf(err) != connect.CodeUnauthenticated {
				t.Errorf("%s, %s token: err = %v, want unauthenticated", kind, name, err)
			}
		}
	}
	// And no handler ran
	if n, _ := handlers.snapshot(); n != 0 {
		t.Fatalf("handler ran %d times for refused calls", n)
	}
}

func TestAuthInterceptor_MapsAuthenticatorRefusals(t *testing.T) {
	// Given Authenticator refusals and the code each must reach the client as
	type refusal struct {
		principal gearbox.Principal
		err       error
		wantCode  connect.Code
	}
	refusals := map[string]refusal{
		"connect error passes as is":        {nil, connect.NewError(connect.CodePermissionDenied, errors.New("nope")), connect.CodePermissionDenied},
		"gearbox sentinel maps through Err": {nil, gearbox.ErrUnauthenticated, connect.CodeUnauthenticated},
		"raw error is internal, withheld":   {nil, errors.New("select secret"), connect.CodeInternal},
		"no principal, no error refuses":    {nil, nil, connect.CodeUnauthenticated},
	}
	for name, r := range refusals {
		t.Run(name, func(t *testing.T) {
			refusingAuthn := func(context.Context, connect.Spec, http.Header) (gearbox.Principal, error) {
				return r.principal, r.err
			}
			handlers := &seen{}
			base := serve(t, handlers, connectgear.Options(connectgear.AuthInterceptor(refusingAuthn)))
			for kind, callWith := range callKinds(t, base) {
				// When a call is made
				err := callWith("")
				// Then it gets the mapped code and never the raw error text
				if connect.CodeOf(err) != r.wantCode {
					t.Errorf("%s: err = %v, want %v", kind, err, r.wantCode)
				}
				if err != nil && strings.Contains(err.Error(), "select secret") {
					t.Errorf("%s: raw error reached the client: %v", kind, err)
				}
			}
			// And no handler ran
			if n, _ := handlers.snapshot(); n != 0 {
				t.Fatalf("handler ran %d times for refused calls", n)
			}
		})
	}
}

func TestOptions_WithholdsHandlerPanics(t *testing.T) {
	// Given handlers that panic with secrets in the panic value
	admitAll := func(context.Context, connect.Spec, http.Header) (gearbox.Principal, error) { return "u", nil }
	base := serve(t, &seen{}, connectgear.Options(connectgear.AuthInterceptor(admitAll)))
	// When the unary and the streaming one are called
	panicErrs := map[string]error{"unary": call(t, base, procPanic, ""), "stream": callStream(t, base, procSPanic, "")}
	// Then each comes back internal with the panic withheld
	for kind, err := range panicErrs {
		if connect.CodeOf(err) != connect.CodeInternal {
			t.Errorf("%s: err = %v, want internal", kind, err)
		}
		if err != nil && (strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "relation")) {
			t.Errorf("%s: the panic reached the client: %v", kind, err)
		}
	}
}

func TestOptions_LimitsTheRequestSize(t *testing.T) {
	// Given a public handler mounted with Options and a request at the limit
	handlers := &seen{}
	authn := connectgear.Bearer(verifier(t, chainSecret))
	base := serve(t, handlers, connectgear.Options(connectgear.AuthInterceptor(authn, connectgear.PublicProcedures(procPublic))))
	client := connect.NewClient[str, str](http.DefaultClient, base+procPublic)
	// A StringValue of n bytes encodes as n+tag+varint(n) bytes, so this is over.
	overLimit := strings.Repeat("a", connectgear.DefaultMaxRequestBytes)
	// When the over-size request and a small one are sent
	_, overErr := client.CallUnary(context.Background(), connect.NewRequest(wrapperspb.String(overLimit)))
	callsAfterOver, _ := handlers.snapshot()
	_, smallErr := client.CallUnary(context.Background(), connect.NewRequest(wrapperspb.String(overLimit[:1024])))
	// Then the over-size one is resource_exhausted before the handler runs
	if connect.CodeOf(overErr) != connect.CodeResourceExhausted {
		t.Fatalf("over-size: err = %v, want resource_exhausted", overErr)
	}
	if callsAfterOver != 0 {
		t.Fatalf("handler ran %d times for an over-size request", callsAfterOver)
	}
	if smallErr != nil {
		t.Fatalf("small request: %v", smallErr)
	}
	if connectgear.DefaultMaxRequestBytes != 8<<20 {
		t.Fatalf("DefaultMaxRequestBytes = %d", connectgear.DefaultMaxRequestBytes)
	}
}
