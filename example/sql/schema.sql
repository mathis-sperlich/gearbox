-- A tiny shop: customers place orders for a product; orders move through a
-- lifecycle. Money is integer minor units (cents); the engine never invents a
-- value, the Go action bodies do.
create table if not exists customers (
    id                  uuid   primary key default gen_random_uuid(),
    name                text   not null,
    lifetime_spend_cents bigint not null default 0
);

create table if not exists products (
    id          uuid   primary key default gen_random_uuid(),
    name        text   not null,
    stock       int    not null,
    price_cents bigint not null
);

create table if not exists orders (
    id            uuid        primary key default gen_random_uuid(),
    customer_id   uuid        not null references customers (id),
    product_id    uuid        not null references products (id),
    quantity      int         not null,
    status        text        not null default 'placed',
    total_cents   bigint      not null,
    currency      text        not null default 'USD',
    payment_ref   text        not null default '',
    tracking_code text        not null default '',
    cancel_reason text        not null default '',
    placed_at     timestamptz not null,
    paid_at       timestamptz,
    shipped_at    timestamptz,
    updated_at    timestamptz not null
);

create table if not exists order_events (
    id       uuid        primary key default gen_random_uuid(),
    order_id uuid        not null references orders (id),
    kind     text        not null,
    detail   text        not null default '',
    at       timestamptz not null
);
