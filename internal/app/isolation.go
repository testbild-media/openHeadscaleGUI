package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/testbild-media/openHeadscaleGUI/internal/gateway"
	"github.com/testbild-media/openHeadscaleGUI/internal/store"
)

// isolationMarker identifies the ACL policy ohg writes for isolated
// instances.
const isolationMarker = "Von OpenHeadscaleGUI verwaltet"

// IsolatedPolicy is the ACL policy of an instance whose devices must not
// see each other: every device may only talk to the server (.1) – for
// bridges from other instances, port forwards and the exit node – and the
// server may reach every device. Peers only receive each other when a rule
// connects them, so the devices do not even appear in each other's lists.
func IsolatedPolicy(inst *store.Instance) string {
	v4, v6, bridges := ReservedIPv4(inst), ReservedIPv6(inst), BridgePrefixOf(inst)
	return fmt.Sprintf(`// %s: Die Geräte dieser Instanz sind voneinander isoliert und
// erreichen nur den Server (%s) und die über Brücken freigegebenen Hosts
// (%s) – dort prüft der Server jedes Gerät einzeln – sowie Port-Forwards und
// den Exit-Node. Änderungen hier werden überschrieben;
// die Isolation lässt sich in den Einstellungen der Instanz abschalten.
{
  "acls": [
    {"action": "accept", "src": ["%s@"], "dst": ["*:*"]},
    {"action": "accept", "src": ["*"], "dst": ["%s/32:*", "%s/128:*", "%s:*"]},
    {"action": "accept", "src": ["*"], "dst": ["autogroup:internet:*"]},
  ],
}
`, isolationMarker, v4, bridges, gateway.SystemUser, v4, v6, bridges)
}

// applyIsolation writes the isolation policy, or – when isolation was
// switched off – replaces ohg's isolation policy by the default policy. A
// policy written by the user is left alone.
func (a *App) applyIsolation(ctx context.Context, inst *store.Instance) error {
	c, err := a.Client(ctx, inst)
	if err != nil {
		return err
	}
	cur, _ := c.GetPolicy(ctx)
	if inst.IsolateClients {
		want := IsolatedPolicy(inst)
		if cur == want {
			return nil
		}
		return hsErr(c.SetPolicy(ctx, want))
	}
	if strings.Contains(cur, isolationMarker) {
		return hsErr(c.SetPolicy(ctx, DefaultPolicy))
	}
	return nil
}
