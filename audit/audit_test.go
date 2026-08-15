package audit

import (
	"strings"
	"testing"
)

func TestSQL_IdempotentAndComplete(t *testing.T) {
	cfg := Config{Entities: []string{"orders", "b_things", "orders", "secrets", "entity_changes"}, Exclude: []string{"secrets"}}
	sql := SQL(cfg)

	for _, want := range []string{
		"create table if not exists entity_changes",
		"create or replace function record_entity_change()",
		"current_setting('gearbox.source', true)",
		"drop trigger if exists orders_audit on orders",
		"to_regclass('public.b_things')",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q", want)
		}
	}
	// excluded, deduped, and never audits the audit table itself
	if strings.Contains(sql, "secrets_audit") || strings.Contains(sql, "entity_changes_audit") {
		t.Error("Exclude / self-audit guard failed")
	}
	if strings.Count(sql, "orders_audit") != 2 { // one drop + one create
		t.Errorf("orders stanza not deduplicated: %d mentions", strings.Count(sql, "orders_audit"))
	}
	// sorted output is stable
	if strings.Index(sql, "b_things_audit") > strings.Index(sql, "orders_audit") {
		t.Error("triggers not sorted")
	}
}

func TestTriggersSQL_CustomFunctionName(t *testing.T) {
	sql := TriggersSQL(Config{Function: "my_audit_fn", Entities: []string{"orders"}})
	if !strings.Contains(sql, "for each row execute function my_audit_fn()") {
		t.Fatalf("custom function name not used:\n%s", sql)
	}
}
