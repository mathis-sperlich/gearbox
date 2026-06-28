package orders

import "testing"

// The whole state machine boots and validates: the transitions map wires every
// action, and the graph carries the four statuses + three actions.
func TestWorkflowBootsAndValidates(t *testing.T) {
	if err := orderWorkflow.Validate(); err != nil {
		t.Fatal(err)
	}
	g := orderWorkflow.Graph()
	if len(g.Statuses) != 4 || len(g.Actions) != 3 {
		t.Fatalf("graph = %d statuses / %d actions, want 4/3", len(g.Statuses), len(g.Actions))
	}
	if g.Entity != "orders" {
		t.Fatalf("entity = %q", g.Entity)
	}
}
