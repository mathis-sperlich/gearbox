package gearbox

// Graph is the introspectable snapshot of a workflow. It carries no tenant data
// — only the state-machine shape — so it is safe to expose unauthenticated
// (e.g. as an RPC a frontend reads to render the lifecycle).
type Graph struct {
	Entity       string             `json:"entity"`
	WorkflowName string             `json:"workflow_name"`
	StatusColumn string             `json:"status_column"`
	Statuses     []string           `json:"statuses"`
	Initial      []string           `json:"initial"`
	Actions      []ActionDescriptor `json:"actions"`
}

// Graph derives the introspectable graph from a workflow's registry.
func (wf *Workflow[T, S]) Graph() Graph {
	return Graph{
		Entity:       wf.Entity,
		WorkflowName: wf.WorkflowName,
		StatusColumn: wf.StatusColumn,
		Statuses:     append([]string(nil), wf.Statuses...),
		Initial:      append([]string(nil), wf.Initial...),
		Actions:      wf.Actions(),
	}
}
