-- The whole shop runs on gearbox's generic CRUD helpers (Get/Insert/Update/…)
-- over the sqlc-generated structs — so there are no per-operation queries here.
-- This one stays as sqlc: a FOR UPDATE SKIP LOCKED drain has no CRUD equivalent,
-- and it shows the escape hatch — drop to sqlc whenever a query earns it.

-- name: ListExpiredPlacedOrders :many
select id from orders
where status = 'placed' and placed_at < $1::timestamptz
order by id
for update skip locked;
