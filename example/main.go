// Command example wires gearbox behind a Connect-RPC service, end to end:
// pool → engine → typed handlers calling gearbox.Run. The workflow logic lives
// in orders/actions.go; this file is wiring only.
//
//	DATABASE_URL=postgres://...  JWT_SECRET=dev-secret  go run ./example
//
// Then, with a token whose `roles` claim has "clerk" (or "admin"):
//
//	id=$(curl -s -XPOST localhost:8080/seed | jq -r .order_id)
//	curl -s -XPOST localhost:8080/orders.v1.OrdersService/Pay \
//	     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
//	     -d "{\"id\":\"$id\",\"payment_ref\":\"ch_123\"}"
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/validate"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mathis-sperlich/gearbox"
	"github.com/mathis-sperlich/gearbox/authjwt"
	"github.com/mathis-sperlich/gearbox/connectgear"
	shopdb "github.com/mathis-sperlich/gearbox/example/db"
	ordersv1 "github.com/mathis-sperlich/gearbox/example/gen/ordersv1"
	"github.com/mathis-sperlich/gearbox/example/gen/ordersv1/ordersv1connect"
	"github.com/mathis-sperlich/gearbox/example/orders"
)

func main() {
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, mustEnv("DATABASE_URL"))
	must(err)
	defer pool.Close()

	// The engine: plain-pool transactions + role-check authz. Swap PoolTx for a
	// custom TxRunner to bind the principal into an RLS transaction.
	eng := gearbox.NewEngine(gearbox.Config{
		Tx:    gearbox.PoolTx(pool),
		Authz: authorize,
	})

	verifier, err := authjwt.NewVerifier(mustEnv("JWT_SECRET"))
	must(err)
	validator := validate.NewInterceptor() // buf.validate rules, enforced pre-handler

	svc := &ordersServer{eng: eng}
	path, handler := ordersv1connect.NewOrdersServiceHandler(svc,
		connect.WithInterceptors(authInterceptor(verifier), validator))

	mux := http.NewServeMux()
	mux.Handle(path, handler)
	mux.HandleFunc("/seed", seed(pool))

	orders.StartAutoCancel(ctx, pool, eng, time.Hour)

	addr := envOr("LISTEN_ADDR", ":8080")
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ordersServer implements the generated OrdersService: each handler is
// principal → gearbox.Run → error map. The engine does the rest.
type ordersServer struct {
	ordersv1connect.UnimplementedOrdersServiceHandler
	eng *gearbox.Engine
}

func (s *ordersServer) Pay(ctx context.Context, req *connect.Request[ordersv1.PayRequest]) (*connect.Response[ordersv1.PayResponse], error) {
	resp, err := gearbox.Run(ctx, s.eng, connectgear.PrincipalFrom(ctx), orders.Pay, req.Msg.GetId(), req.Msg)
	if err != nil {
		return nil, connectgear.Err(err)
	}
	return connect.NewResponse(resp), nil
}

func (s *ordersServer) Ship(ctx context.Context, req *connect.Request[ordersv1.ShipRequest]) (*connect.Response[ordersv1.ShipResponse], error) {
	resp, err := gearbox.Run(ctx, s.eng, connectgear.PrincipalFrom(ctx), orders.Ship, req.Msg.GetId(), req.Msg)
	if err != nil {
		return nil, connectgear.Err(err)
	}
	return connect.NewResponse(resp), nil
}

// Cancel serves one order (selector.id) or a batch (selector.ids) through the
// same action — RunAll runs the batch in a single all-or-nothing transaction.
func (s *ordersServer) Cancel(ctx context.Context, req *connect.Request[ordersv1.CancelRequest]) (*connect.Response[ordersv1.CancelResponse], error) {
	results, err := gearbox.RunAll(ctx, s.eng, connectgear.PrincipalFrom(ctx), orders.Cancel, req.Msg.GetSelector(), req.Msg)
	if err != nil {
		return nil, connectgear.Err(err)
	}
	resp := &ordersv1.CancelResponse{Cancelled: int32(len(results))}
	for _, r := range results {
		resp.RefundedCents += r.GetRefundedCents()
	}
	return connect.NewResponse(resp), nil
}

// authorize is the whole access-control policy: an action names a Role, allowed
// when the JWT carries it (or "admin"). gearbox ships no RBAC — this is all of it.
func authorize(_ context.Context, p gearbox.Principal, a gearbox.ActionDescriptor, _ []string) error {
	if a.Role == "" {
		return nil
	}
	for _, r := range authjwt.RolesOf(p) {
		if r == a.Role || r == "admin" {
			return nil
		}
	}
	return fmt.Errorf("%w: %q needs role %q", gearbox.ErrUnauthorized, a.Name, a.Role)
}

// authInterceptor verifies the bearer token and stores the claims as the
// Principal for handlers to hand to gearbox.
func authInterceptor(v *authjwt.Verifier) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			claims, err := v.VerifyBearer(req.Header().Get("Authorization"))
			if err != nil {
				return nil, connectgear.Err(err)
			}
			return next(connectgear.WithPrincipal(ctx, claims), req)
		}
	}
}

// seed creates a customer, a product, and a placed order so the example is
// exercisable — gearbox's CRUD helpers straight off the pool.
func seed(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		fail := func(err error) bool {
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return err != nil
		}
		cust, err := gearbox.Insert(ctx, pool, shopdb.Customer{Name: "Ada Lovelace"})
		if fail(err) {
			return
		}
		prod, err := gearbox.Insert(ctx, pool, shopdb.Product{Name: "Widget", Stock: 100, PriceCents: 1999})
		if fail(err) {
			return
		}
		now := time.Now().UTC()
		ord, err := gearbox.Insert(ctx, pool, shopdb.Order{
			CustomerID: cust.ID, ProductID: prod.ID, Quantity: 2,
			TotalCents: 3998, Currency: "USD", Status: orders.StatusPlaced,
			PlacedAt: now, UpdatedAt: now,
		})
		if fail(err) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"customer_id": cust.ID, "product_id": prod.ID, "order_id": ord.ID,
		})
	}
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing required env: %s", k)
	}
	return v
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
