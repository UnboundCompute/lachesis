# Canonical graph contract v2

`Arachne.core` is language-agnostic. It defines graph identities, canonical
node/edge kinds, capability vocabulary, provenance rules, validation and graph
composition. It must not import a language frontend, an ecosystem model or the
legacy compatibility API.

Language-neutral semantic analyses live under `Arachne.core.overlays`. They are
registered and applied sequentially to canonical graphs, returning additive
`GraphDelta` facts with core-owned v2 identities and evidence. An overlay must
not mutate or relabel a compiler fact: alternate dispatch, contextual bindings,
heap locations and other conclusions are represented as separate nodes/edges.

The default direct pipeline currently builds per-function control flow and
branch-sensitive SSA histories, then instantiates call-site contexts,
compiler-emitted parameter/property effects, module singleton/mutable state and
import cycles. Phi nodes retain every incoming definition and branch-correct
reads point to the merged version. Allocation-site heap objects survive aliases,
nested property reads/writes share stable locations, returned allocations are
cloned per call context, and parameter-property effects are applied to the
caller-owned object. After ecosystem models run, a security overlay materializes
compiler/model-tagged sources and sinks and calculates context-stack-aware taint
witnesses. Call entry pushes a call-site context and return flow must pop that
same context, preventing two calls to a shared callee from contaminating each
other. Declarative runtime models add library behavior without parsing source;
the async/event overlay turns those facts and compiler `await` operations into
callback registration, scheduling, continuation, event, queue, stream, and
worker edges. Remaining legacy passes are being migrated before the `FileInfo`
compatibility projection itself can be deleted. `run_project_frontends` and the
CLI already use this direct path; `FileInfo` no longer participates in primary
graph construction.

## Ownership

Every v2 ID is ownership-qualified:

```text
v2:<owner>:<namespace>:<kind>:<digest>
```

Valid owners are `frontend`, `core`, `runtime-model` and `framework-model`.
This prevents a compiler fact and an inferred overlay fact from silently sharing
an identity.

## Fact provenance

Every v2 node and edge declares:

- `fact_origin`: `compiler`, `runtime-model`, `framework-model` or `core-inference`.
- `confidence`: `exact`, `high`, `conservative` or `unresolved`.
- `evidence_ids`: required and non-empty for every non-compiler inference.

`fact_origin` is deliberately distinct from domain fields such as a value
definition's `origin=parameter|literal|expression`.

Source-derived nodes additionally carry the complete source interval, content
hash, language, frontend ID and compiler node identity defined in
`provenance.py`.

Language-only data belongs below:

```text
properties.frontend_extensions.<language>
```

The core never interprets this data.

## Version migration

Contract v1 snapshots remain accepted only as migration inputs. They receive
the old structural and source-span checks, while v2 snapshots receive strict
kind, owner, tier, source provenance and evidence validation. Frontends will be
moved to v2 individually; once both registered frontends emit v2 and the legacy
API reads from the completed canonical graph, v1 support can be deleted.
