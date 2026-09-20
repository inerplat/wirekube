package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// The relay dial must not sit on the startup path.
//
// setup() runs before the agent's first sync, and the first sync is what puts
// transport paths into the Bind. While setup is blocked the Bind has no path
// for any peer, so the node receives normally and cannot send a thing.
//
// Measured on a ten-node cluster by restarting one agent under continuous ping.
// The node whose relay address does not answer lost 10.5 s of outbound traffic;
// a node whose relay answers lost 0.5 s. A packet capture on the stalled node
// showed 15801 inbound packets with no gap and one 10.9 s gap outbound, ending
// exactly when the first SetPeerPath ran. Backgrounding the dial took the same
// node to 1.0 s.
//
// This is a source-level check because the behaviour cannot be reached from a
// test process. What stalls the dial is a SYN that goes unanswered, and a
// listener that accepts and then stays silent does not reproduce it: initRelay
// returns in about 2 ms against one. Producing real silence needs a firewall
// rule on the host, which a unit test has no business installing. So the
// property fixed here is the one that matters and is checkable: the call is
// not awaited.
func TestRelayDialIsNotOnTheStartupPath(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "agent.go", nil, 0)
	if err != nil {
		t.Fatalf("parse agent.go: %v", err)
	}

	var found, backgrounded bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "initRelay" {
			return true
		}
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			// A `go func(){ ... }()` whose body calls Connect satisfies the
			// property; so does `go pool.Connect(ctx)` written directly.
			goStmt, ok := inner.(*ast.GoStmt)
			if !ok {
				return true
			}
			ast.Inspect(goStmt, func(c ast.Node) bool {
				call, ok := c.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Connect" {
					backgrounded = true
				}
				return true
			})
			return true
		})
		// Any Connect call at all, so a removed call is not read as a pass.
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Connect" {
				found = true
			}
			return true
		})
		return false
	})

	if !found {
		t.Fatal("initRelay no longer calls Connect at all; the relay would never be dialled")
	}
	if !backgrounded {
		t.Error("initRelay awaits the relay dial. setup() blocks for the full dialTimeout " +
			"when the relay address does not answer, and no peer has a Bind path until it returns")
	}
}

// The comment above the dial carries the measurement that justifies it. Losing
// it turns a deliberate choice back into something that looks like an
// oversight, which is how it was written in the first place.
func TestRelayDialKeepsItsRationale(t *testing.T) {
	src, err := parser.ParseFile(token.NewFileSet(), "agent.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse agent.go: %v", err)
	}
	var text strings.Builder
	for _, g := range src.Comments {
		text.WriteString(g.Text())
	}
	for _, want := range []string{"Dial the relay off the startup path", "SetPeerPath"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("the rationale for backgrounding the relay dial no longer mentions %q", want)
		}
	}
}

// Work that needs an established relay must run from initRelay's callback, not
// after the call.
//
// initRelay returns before the dial completes, so a.relayPool.IsConnected() is
// false at the return in the ordinary case, even when the relay answers
// instantly. setup used to gate cone refinement on exactly that check.
// DetectPortRestriction has a single caller, and skipping it leaves a
// port-restricted cone node classified as plain cone for the life of the
// process: the periodic re-classifier deliberately refuses to draw that
// distinction, so nothing recovers it. The node then keeps probing direct
// paths to symmetric peers that cannot exist.
func TestRelayDependentWorkDoesNotGateOnIsConnectedAfterInitRelay(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "agent.go", nil, 0)
	if err != nil {
		t.Fatalf("parse agent.go: %v", err)
	}

	var offenders []string
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "setup" {
			return true
		}
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "IsConnected" {
				return true
			}
			offenders = append(offenders, fset.Position(call.Pos()).String())
			return true
		})
		return false
	})

	if len(offenders) > 0 {
		t.Errorf("setup gates on relay IsConnected at %s; the dial has not finished by then, "+
			"so the guarded work is skipped even for a reachable relay. Pass it to initRelay "+
			"as the onConnected callback instead", strings.Join(offenders, ", "))
	}
}

// The dial goroutine must use the pool it was handed, not re-read a.relayPool.
//
// maybeRefreshRelayEndpoint closes the current pool, sets the field to nil, and
// re-enters initRelay whenever a managed endpoint changes. A goroutine that
// dereferences the field when it happens to run can find nil, or dial the
// replacement concurrently with the replacement's own dial, racing Pool.cancel
// and starting a second discovery loop.
func TestRelayDialUsesTheCapturedPool(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "agent.go", nil, 0)
	if err != nil {
		t.Fatalf("parse agent.go: %v", err)
	}

	var viaField bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "initRelay" {
			return true
		}
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			goStmt, ok := inner.(*ast.GoStmt)
			if !ok {
				return true
			}
			ast.Inspect(goStmt, func(c ast.Node) bool {
				call, ok := c.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Connect" {
					return true
				}
				// a.relayPool.Connect(...) reads the mutable field.
				if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "relayPool" {
					viaField = true
				}
				return true
			})
			return true
		})
		return false
	})

	if viaField {
		t.Error("the background dial reads a.relayPool instead of a captured local; " +
			"maybeRefreshRelayEndpoint can nil or replace that field while the dial is outstanding")
	}
}
