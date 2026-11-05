package features_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
	procSend   = "/test.v1.Sheets/Send"   // gated unary
	procOpen   = "/test.v1.Sheets/Open"   // ungated unary
	procWatch  = "/test.v1.Sheets/Watch"  // gated server stream
	procTail   = "/test.v1.Sheets/Tail"   // ungated server stream
	procPublic = "/test.v1.Sheets/Public" // ungated, no credentials needed
)

// The test service's messages are StringValues whose value is the scope.
type scopeMsg = wrapperspb.StringValue

func scopeOf(msg any) string { return msg.(*scopeMsg).GetValue() }

func newGate(t *testing.T) connect.Interceptor {
	t.Helper()
	g, err := features.NewGate(flagValue, map[string]flag{procSend: flagSheets, procWatch: flagSheets}, scopeOf)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// serve runs the test service behind authn and g.
func serve(t *testing.T, authn connectgear.Authenticator, g connect.Interceptor) string {
	t.Helper()
	opts := connectgear.Options(
		connectgear.AuthInterceptor(authn, connectgear.PublicProcedures(procPublic)),
		g,
	)
	unary := func(context.Context, *connect.Request[scopeMsg]) (*connect.Response[scopeMsg], error) {
		return connect.NewResponse(&scopeMsg{}), nil
	}
	stream := func(_ context.Context, _ *connect.Request[scopeMsg], out *connect.ServerStream[scopeMsg]) error {
		return out.Send(&scopeMsg{})
	}
	mux := http.NewServeMux()
	for _, p := range []string{procSend, procOpen, procPublic} {
		mux.Handle(p, connect.NewUnaryHandler(p, unary, opts))
	}
	for _, p := range []string{procWatch, procTail} {
		mux.Handle(p, connect.NewServerStreamHandler(p, stream, opts))
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func tokenWith(t *testing.T, v authjwt.Signer, d features.Decisions[flag]) string {
	t.Helper()
	signIn := authjwt.ClaimsSet{Subject: "user-1"}
	d.Embed(&signIn)
	token, _, err := v.Sign(signIn, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func call(base, proc, token, scope string) error {
	req := connect.NewRequest(wrapperspb.String(scope))
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	_, err := connect.NewClient[scopeMsg, scopeMsg](http.DefaultClient, base+proc).CallUnary(context.Background(), req)
	return err
}

func callStream(base, proc, token, scope string) error {
	req := connect.NewRequest(wrapperspb.String(scope))
	req.Header().Set("Authorization", "Bearer "+token)
	st, err := connect.NewClient[scopeMsg, scopeMsg](http.DefaultClient, base+proc).CallServerStream(context.Background(), req)
	if err != nil {
		return err
	}
	defer st.Close()
	for st.Receive() {
	}
	return st.Err()
}

func wantDenied(t *testing.T, what string, err error) {
	t.Helper()
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("%s: err = %v, want permission_denied", what, err)
	}
}

func TestGate_AllowsAFeatureOnInTheRequestScope(t *testing.T) {
	// Given a caller with FLAG_SHEETS granted in orgA, and one granted globally
	v := newVerifier(t)
	base := serve(t, connectgear.Bearer(v), newGate(t))
	grantedInOrgA := tokenWith(t, v, inScope(orgA, flagSheets, true))
	grantedGlobally := tokenWith(t, v, global(flagSheets, true))

	// When they call the gated procedures in a scope where it is on
	// Then the calls succeed
	if err := call(base, procSend, grantedInOrgA, orgA); err != nil {
		t.Fatalf("scope grant: %v", err)
	}
	if err := call(base, procSend, grantedGlobally, orgB); err != nil {
		t.Fatalf("global grant: %v", err)
	}
	if err := callStream(base, procWatch, grantedInOrgA, orgA); err != nil {
		t.Fatalf("stream, scope grant: %v", err)
	}
}

func TestGate_PassesUngatedProcedures(t *testing.T) {
	// Given a caller with no decisions and an unauthenticated caller
	v := newVerifier(t)
	base := serve(t, connectgear.Bearer(v), newGate(t))
	noDecisions := tokenWith(t, v, features.Decisions[flag]{})

	// When they call procedures the gate doesn't list
	// Then the gate lets them through
	if err := call(base, procOpen, noDecisions, ""); err != nil {
		t.Fatalf("ungated: %v", err)
	}
	if err := call(base, procPublic, "", ""); err != nil {
		t.Fatalf("ungated public, unauthenticated: %v", err)
	}
	if err := callStream(base, procTail, noDecisions, ""); err != nil {
		t.Fatalf("ungated stream: %v", err)
	}
}

func TestGate_FailsClosed(t *testing.T) {
	// Given callers whose tokens don't turn FLAG_SHEETS on in the request scope
	v := newVerifier(t)
	base := serve(t, connectgear.Bearer(v), newGate(t))
	grantedInOrgA := tokenWith(t, v, inScope(orgA, flagSheets, true))
	grantedGlobally := tokenWith(t, v, global(flagSheets, true))
	refusedCalls := []struct {
		name, token, scope string
	}{
		{"no decisions", tokenWith(t, v, features.Decisions[flag]{}), orgA},
		{"no scope", grantedInOrgA, ""},
		{"scope '*' with a global grant", grantedGlobally, "*"},
		{"global kill switch", tokenWith(t, v, global(flagSheets, false)), orgA},
		{"another scope's grant", grantedInOrgA, orgB},
		{"scope denial over a global grant", tokenWith(t, v, both(orgA, flagSheets, false, true)), orgA},
	}
	for _, rc := range refusedCalls {
		// When they call the gated unary and stream
		// Then both are refused
		wantDenied(t, rc.name, call(base, procSend, rc.token, rc.scope))
		wantDenied(t, rc.name+" (stream)", callStream(base, procWatch, rc.token, rc.scope))
	}
}

func TestGate_RefusesPrincipalsWithoutClaims(t *testing.T) {
	// Given an authenticator whose principal isn't *authjwt.Claims
	apiKeyAuth := func(context.Context, connect.Spec, http.Header) (gearbox.Principal, error) {
		return "api-key-42", nil
	}
	base := serve(t, apiKeyAuth, newGate(t))
	// When it calls a gated procedure
	err := call(base, procSend, "", orgA)
	// Then it has no decisions and is refused
	wantDenied(t, "foreign principal", err)
}

func TestGate_RefusesMalformedClaims(t *testing.T) {
	// Given principals whose features claim isn't the shape the app signs
	g := newGate(t)
	malformedClaims := map[string]string{
		"not an object":       `"FLAG_SHEETS"`,
		"bucket not a map":    `{"` + orgA + `":"FLAG_SHEETS"}`,
		"decision not a bool": `{"` + orgA + `":{"FLAG_SHEETS":"yes"}}`,
	}
	for name, claim := range malformedClaims {
		malformed := &authjwt.Claims{Subject: "user-1", Raw: []byte(`{"features":` + claim + `}`)}
		ctx := connectgear.WithPrincipal(context.Background(), malformed)
		// When it sends a gated stream message
		conn := &fakeConn{procedure: procWatch, in: []string{orgA}}
		err := g.WrapStreamingHandler(func(_ context.Context, c connect.StreamingHandlerConn) error {
			return c.Receive(&scopeMsg{})
		})(ctx, conn)
		// Then it is refused
		wantDenied(t, name, err)
	}
}

func TestNewGate_RefusesUnknownFeatures(t *testing.T) {
	// Given gates on the zero value and on an undefined value
	notFeatures := []flag{flagUnspecified, flag(99)}
	for _, f := range notFeatures {
		// When the gate is built
		_, err := features.NewGate(flagValue, map[string]flag{procSend: f}, scopeOf)
		// Then it is refused
		if err == nil {
			t.Errorf("gate on %v accepted", f)
		}
	}
}

func TestNewGate_RequiresScopeOf(t *testing.T) {
	// Given a gate with no way to read the scope off a message
	// When it is built
	_, err := features.NewGate(flagValue, map[string]flag{}, nil)
	// Then it is refused
	if err == nil {
		t.Fatal("accepted a gate without scopeOf")
	}
}

// fakeConn is a bidi handler stream whose Receive yields the queued scopes
// and whose Send counts.
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
	msg.(*scopeMsg).Value, f.in = f.in[0], f.in[1:]
	return nil
}

func (f *fakeConn) Send(any) error { f.sent++; return nil }

// runBidi runs body as the handler of a bidi stream on procedure receiving in.
func runBidi(ctx context.Context, g connect.Interceptor, procedure string, in []string, body func(connect.StreamingHandlerConn) error) (*fakeConn, error) {
	conn := &fakeConn{procedure: procedure, in: in}
	err := g.WrapStreamingHandler(func(_ context.Context, c connect.StreamingHandlerConn) error {
		return body(c)
	})(ctx, conn)
	return conn, err
}

func TestGate_BidiSendsAfterAPassedMessage(t *testing.T) {
	// Given a caller granted in orgA on a gated bidi stream
	grantedInOrgA := connectgear.WithPrincipal(context.Background(), &authjwt.Claims{
		Subject: "user-1",
		Raw:     []byte(`{"features":{"` + orgA + `":{"FLAG_SHEETS":true}}}`),
	})
	// When the handler receives an orgA message, sends, then receives an orgB one
	var secondReceive, sendAfterRefusal error
	conn, err := runBidi(grantedInOrgA, newGate(t), procWatch, []string{orgA, orgB}, func(c connect.StreamingHandlerConn) error {
		if err := c.Receive(&scopeMsg{}); err != nil {
			return err
		}
		if err := c.Send(&scopeMsg{}); err != nil {
			return err
		}
		secondReceive = c.Receive(&scopeMsg{})
		sendAfterRefusal = c.Send(&scopeMsg{})
		return nil
	})
	// Then only the send after the passed message goes out
	if err != nil || conn.sent != 1 {
		t.Fatalf("err = %v, sent %d; want one send", err, conn.sent)
	}
	wantDenied(t, "second message, other scope", secondReceive)
	wantDenied(t, "send after a refused message", sendAfterRefusal)
}

func TestGate_BidiRefusesSendBeforeReceive(t *testing.T) {
	// Given a caller granted in orgA on a gated bidi stream
	grantedInOrgA := connectgear.WithPrincipal(context.Background(), &authjwt.Claims{
		Subject: "user-1",
		Raw:     []byte(`{"features":{"` + orgA + `":{"FLAG_SHEETS":true}}}`),
	})
	// When the handler sends before reading anything
	conn, err := runBidi(grantedInOrgA, newGate(t), procWatch, []string{orgA}, func(c connect.StreamingHandlerConn) error {
		return c.Send(&scopeMsg{})
	})
	// Then nothing leaks
	wantDenied(t, "send before receive", err)
	if conn.sent != 0 {
		t.Fatal("message sent before any check")
	}
}
