# Claude handoff: bundle export gates

This handoff records the Lachesis/Arachne work that remains before the local
maintainer-pilot corpus can cover ordinary, findings-free repositories. It is
deliberately separate from the app repositories: Design Map and Explorer should
not weaken their bundle validators to hide exporter failures.

## Required behavior

1. A code-understanding bundle may contain zero security findings. It should
   still export the repository purpose, source-backed declarations/modules, and
   any available entrypoints or paths.
2. A repository without a three-hop path must receive a valid reduced bundle or
   a structured reduced-coverage result. The CLI must not leak an unhandled
   `ValueError` or write a misleading candidate bundle.
3. Direct static C calls should produce `READS_CALLEE` edges when the frontend
   can resolve them, including recursive calls.
4. Module relationship evidence should not be starved by the comprehension
   node budget or by unassignable value/dataflow nodes. Any added relationship
   must remain grounded in full-graph call evidence.
5. Source resolution must remain scoped to the requested repository path and
   must never inherit an unrelated fixture or stale cache source tree.
6. Public v2 source nodes must satisfy the provenance contract, or the export
   must stop with a bounded, actionable diagnostic that identifies the missing
   normalization step.

## Evidence

The local QA corpus reproduces the current failures on:

- `sindresorhus/p-queue`: no security findings, so export currently rejects
  an otherwise useful TypeScript repository.
- `parson`: ordinary C calls are parsed but no `READS_CALLEE` edges are emitted,
  so the source-backed path gate rejects the repository.
- bounded Flask tracing: stale source resolution and v2 provenance validation
  fail before a candidate-ready bundle is written.

See `qa-stress-test/reports/CLAUDE-ENGINE-HANDOFF.md` and
`qa-stress-test/reports/PROD-READINESS.md` for the full reproduction notes.

## Bounded acceptance

Use local fixtures only. Keep each run under 90 seconds and 768 MB, cap flows
to three per family, and place graph stores, caches, and output bundles under a
unique temporary directory. Remove that directory in a `finally`/trap after
each run. Do not run AWS or retain generated graph databases in this repository.

Acceptance must include:

- a findings-free repository that exports a schema-valid reduced or full bundle;
- a shallow-call repository that exports a schema-valid reduced result;
- a C fixture with at least one resolved direct call;
- a source-path isolation test using a temporary repository;
- existing Arachne bundle tests and the local Design Map/Explorer smoke checks.

Until these gates pass, do not mark the maintainer-pilot map set complete.
