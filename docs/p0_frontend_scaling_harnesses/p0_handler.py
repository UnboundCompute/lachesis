"""The decisive check: do the archive/addAll HANDLERS clear transitively now?

On api/v1-only scope, siblings' guardedness() chase reached the delegated fn but saw an
empty body -> handler stayed 'unguarded' (FP). Now the delegated body is class=guard, so
the chase should flip the handler to guarded:true, transitive:true -- IF the cross-file
CALLS edge (handler -> executeArchiveRoom) resolved in this build.
"""
import sys, json
sys.path = [p for p in sys.path if "jobs/e5c7f439/tmp" not in p and p not in ("", ".")]
sys.path.insert(0, "/Users/riyandhiman/project/unboundcompute/arachne")
from nav.graph_store import GraphStore
from nav.siblings import SiblingDiff
from nav.symbol_index import callees as callees_of, callers as callers_of

GRAPH = sys.argv[1] if len(sys.argv) > 1 else "/Users/riyandhiman/.lachesis/graphs/rc_server.kuzu"
store = GraphStore.load(GRAPH)
store.ensure_dataflow_tier()
sd = SiblingDiff(store)

# Find the api/v1 channels handlers by (file, line-ish). We look for functions in
# api/v1/channels.ts and print each with its callees + guardedness.
targets = []
for e in store.entries:
    if e["granularity"] in ("function", "method") and (e.get("file") or "").endswith("api/v1/channels.ts"):
        targets.append(e)

print(f"functions in api/v1/channels.ts: {len(targets)}")

# The archive handler calls executeArchiveRoom; addAll calls addAllUserToRoomFn. Find the
# handler nodes whose direct callees include those delegated targets.
DELEG = {"executeArchiveRoom", "addAllUserToRoomFn"}
for e in sorted(targets, key=lambda x: x["line"]):
    callee_names = {c.get("name") for c in callees_of(store.gl, e["node_id"])}
    hit = DELEG & {c for c in callee_names if c}
    if hit:
        g = sd.guardedness(e["node_id"])
        print(f"\nHANDLER {e['file']}:{e['line']}  name={e.get('name')!r}")
        print(f"  direct callees include delegated: {sorted(hit)}")
        print(f"  guardedness -> {json.dumps(g)}")

# Also directly probe: for each delegated target, who calls it (reverse), to confirm the
# cross-file edge exists at all.
print("\n=== cross-file CALLS edge check (callers of the delegated targets) ===")
for name in ["executeArchiveRoom", "addAllUserToRoomFn"]:
    hits = store.resolve(name)
    callers = []
    for h in hits:
        for c in callers_of(store.gl, h["node_id"]):
            callers.append((c.get("name"), c.get("file"), c.get("line")))
    uniq = sorted(set(callers))
    print(f"  {name}: {len(uniq)} caller-node(s)")
    for nm, f, ln in uniq[:8]:
        print(f"    <- {nm} @ {f}:{ln}")
