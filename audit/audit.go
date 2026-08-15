// Package audit emits the Postgres DDL that turns gearbox's source
// attribution into a queryable audit trail: a changes table, a generic
// trigger function that reads the engine's transaction-local GUC (see
// gearbox.GUCSourceWriter — attribution is on by default), and one
// AFTER INSERT/UPDATE/DELETE trigger per entity.
//
// Emit-only: the package never touches a database. Feed the SQL to your
// migration tool. Everything is idempotent — CREATE TABLE IF NOT EXISTS,
// CREATE OR REPLACE FUNCTION, DROP TRIGGER IF EXISTS — so re-running after
// registering a new workflow is safe. By default triggers cover every
// entity registered via gearbox.NewWorkflow; hosts with their own audit
// substrate can use TriggersSQL alone against their existing function.
package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mathis-sperlich/gearbox"
)

// Config parameterizes the emitted DDL. The zero value is fully usable.
type Config struct {
	// GUC is the transaction-local setting the trigger function reads.
	// Defaults to gearbox.DefaultGUC ("gearbox.source") — match your
	// engine's GUCSourceWriter.
	GUC string
	// Table is the audit table name. Defaults to "entity_changes".
	Table string
	// Function is the trigger function name. Defaults to "record_entity_change".
	Function string
	// Entities to wire triggers for. Defaults to gearbox.Entities() — every
	// workflow registered at the time of the call.
	Entities []string
	// Exclude removes entities from the default (or given) set — the opt-out.
	Exclude []string
}

func (c Config) withDefaults() Config {
	if c.GUC == "" {
		c.GUC = gearbox.DefaultGUC
	}
	if c.Table == "" {
		c.Table = "entity_changes"
	}
	if c.Function == "" {
		c.Function = "record_entity_change"
	}
	if c.Entities == nil {
		c.Entities = gearbox.Entities()
	}
	return c
}

// SQL emits the full idempotent script: table, trigger function, and one
// trigger per entity.
func SQL(cfg Config) string {
	cfg = cfg.withDefaults()
	return TableSQL(cfg) + "\n" + FunctionSQL(cfg) + "\n" + TriggersSQL(cfg)
}

// TableSQL emits the audit table (vanilla Postgres, CREATE TABLE IF NOT
// EXISTS). entity_id is text so any primary-key type audits cleanly.
func TableSQL(cfg Config) string {
	cfg = cfg.withDefaults()
	return fmt.Sprintf(`create table if not exists %[1]s (
  id                bigserial primary key,
  occurred_at       timestamptz not null default now(),

  entity_table      text not null,
  entity_id         text not null,
  op                text not null check (op in ('insert','update','delete')),

  old_row           jsonb,                                -- null on insert
  new_row           jsonb,                                -- null on delete
  changed_columns   text[] not null default '{}'::text[], -- update only

  actor_role        text not null,                        -- current_user

  source_kind       text not null default 'crud',
  source_workflow   text,
  source_action     text,
  source_request_id text
);

create index if not exists %[1]s_entity_idx
  on %[1]s (entity_table, entity_id, occurred_at desc);
`, cfg.Table)
}

// FunctionSQL emits the shared trigger function: diffs OLD/NEW into jsonb,
// records the acting role, and stamps source attribution from the engine's
// transaction-local GUC (absent GUC ⇒ source_kind 'crud').
func FunctionSQL(cfg Config) string {
	cfg = cfg.withDefaults()
	return fmt.Sprintf(`create or replace function %[1]s()
returns trigger
language plpgsql
as $$
declare
  v_source  jsonb;
  v_old     jsonb;
  v_new     jsonb;
  v_changed text[] := '{}'::text[];
begin
  begin
    v_source := nullif(current_setting('%[2]s', true), '')::jsonb;
  exception when others then
    v_source := null;
  end;

  if tg_op <> 'INSERT' then v_old := to_jsonb(old); end if;
  if tg_op <> 'DELETE' then v_new := to_jsonb(new); end if;
  if tg_op = 'UPDATE' then
    select coalesce(array_agg(k order by k), '{}'::text[]) into v_changed
      from jsonb_object_keys(v_new) as k
     where v_old -> k is distinct from v_new -> k;
  end if;

  insert into %[3]s (
    entity_table, entity_id, op, old_row, new_row, changed_columns,
    actor_role, source_kind, source_workflow, source_action, source_request_id
  ) values (
    tg_table_name,
    coalesce(v_new ->> 'id', v_old ->> 'id'),
    lower(tg_op),
    v_old, v_new, v_changed,
    current_user,
    coalesce(v_source ->> 'kind', 'crud'),
    v_source ->> 'workflow',
    v_source ->> 'action',
    v_source ->> 'request_id'
  );

  return null; -- AFTER trigger
end;
$$;
`, cfg.Function, cfg.GUC, cfg.Table)
}

// TriggersSQL emits one idempotent trigger stanza per entity (sorted,
// de-duplicated, minus Exclude and the audit table itself). Each stanza is
// guarded by to_regclass so environments missing a table skip silently
// instead of failing the migration.
func TriggersSQL(cfg Config) string {
	cfg = cfg.withDefaults()
	skip := map[string]bool{cfg.Table: true}
	for _, e := range cfg.Exclude {
		skip[e] = true
	}
	seen := map[string]bool{}
	var names []string
	for _, e := range cfg.Entities {
		if skip[e] || seen[e] {
			continue
		}
		seen[e] = true
		names = append(names, e)
	}
	sort.Strings(names)

	out := &strings.Builder{}
	for _, name := range names {
		trig := name + "_audit"
		fmt.Fprintf(out, "do $do$ begin\n")
		fmt.Fprintf(out, "  if to_regclass('public.%s') is null then return; end if;\n", name)
		fmt.Fprintf(out, "  execute $stmt$drop trigger if exists %s on %s$stmt$;\n", trig, name)
		fmt.Fprintf(out, "  execute $stmt$\n")
		fmt.Fprintf(out, "    create trigger %s\n", trig)
		fmt.Fprintf(out, "      after insert or update or delete on %s\n", name)
		fmt.Fprintf(out, "      for each row execute function %s()\n", cfg.Function)
		fmt.Fprintf(out, "  $stmt$;\n")
		fmt.Fprintf(out, "end $do$;\n\n")
	}
	return out.String()
}
