"""P0 experiment: does a broader build scope let `siblings` clear the delegated-guard FPs?

On the api/v1-only graph, siblings called channels.archive / channels.addAll UNGUARDED
because the transitive chase (GUARD_RADIUS=2) reached the delegated fn
(executeArchiveRoom / addAllUserToRoomFn) but its body was out of scope -> empty ->
no hasPermissionAsync visible. On the server-wide graph the delegated bodies are IN
scope, so the chase should reach hasPermissionAsync at hop 2 and flip them to
guarded:true, transitive:true.

Run: python3 p0_rerun.py <graph.kuzu>
"""
import sys, json
sys.path = [p for p in sys.path if "jobs/e5c7f439/tmp" not in p and p not in ("", ".")]
sys.path.insert(0, "/Users/riyandhiman/project/unboundcompute/arachne")

from nav.graph_store import GraphStore
from nav.siblings import SiblingDiff
from nav.guards import GuardProfiles
from nav.call_roles import CallRoles

GRAPH = sys.argv[1] if len(sys.argv) > 1 else "/Users/riyandhiman/.lachesis/graphs/rc_server.kuzu"
store = GraphStore.load(GRAPH)
store.ensure_dataflow_tier()
sd = SiblingDiff(store)
guards = GuardProfiles(store)
roles = CallRoles(store, guards=guards)

# The two delegated targets + the guard they should reach.
DELEGATES = ["executeArchiveRoom", "addAllUserToRoomFn", "hasPermissionAsync"]
print("=== presence of delegated bodies in this scope ===")
for name in DELEGATES:
    hits = store.resolve(name)
    print(f"  {name}: {len(hits)} node(s)")
    for h in hits[:2]:
        prof = guards.profile(h["node_id"])
        callees = [c.get("name") for c in store.gl.calls_from(h["node_id"])][:12]
        print(f"    at {h['file']}:{h['line']}  guard_class={prof['class']} "
              f"conds={prof.get('conditions')} throws={prof.get('throws')}")
        print(f"    callees: {callees}")

# The transitivity test: do the archive/addAll HANDLERS now resolve guarded?
print("\n=== guardedness of the delegated targets (should be class=guard: they throw on !hasPermission) ===")
for name in ["executeArchiveRoom", "addAllUserToRoomFn"]:
    hits = store.resolve(name)
    if hits:
        g = sd.guardedness(hits[0]["node_id"])
        print(f"  {name}: {json.dumps(g)}")

# The headline: siblings differential on the room resolver's callers is NOT how siblings
# groups (it groups by name-family). But the delegated-target guardedness above IS the
# thing that would clear the handler FPs in any caller-axis locator. Also run siblings on
# the delegated targets' own name-family to show transitivity now fires.
print("\n=== siblings on findChannelByIdOrName (name-family, unchanged axis) ===")
hits = store.resolve("findChannelByIdOrName")
if hits:
    d = sd.diff(hits[0])
    print(json.dumps({k: d[k] for k in ("family_key", "family_size", "verdict")}, indent=2))

print("\n[DONE]")
