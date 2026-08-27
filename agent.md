# Lachesis agent guide

Lachesis is a native code-analysis engine with a small Python interface. Treat every
reported item as a **lead**: a question to investigate, never a proof of a bug or safety.

## Fast start

```python
import lachesis

leads = lachesis.scan("./repo")
for lead in leads.top(10):
    print(lead.pattern, lead.file, lead.line)
```

The equivalent CLI entrypoint is:

```sh
lachesis scan ./repo
```

Use `lens="all"` for the whole taxonomy, `lens="flow"` for lifetime-flow leads, or
`lens="guard-diff"` for the guard differential view. Use `Analysis.open(graph)` when a
prebuilt graph should be reused across several questions.

## Trust and execution model

- Pass 1 emits the structural graph and binary Pass-2/Pass-3 sidecars.
- Pass 2 consumes the binary Pass-1 sidecar through the Rust kernel.
- There is no Python analysis fallback. A missing or stale binary sidecar is an error; rebuild
  the graph instead of guessing.
- Python is the CLI/SDK surface and source-language frontend orchestration. Rust performs the
  native graph projection, dataflow, catalog binding, and semantic engine work.
- Protobuf/binary sidecars are the internal interchange format. JSON is only an explicit output
  format when a caller requests `to_json()` or CLI `--json`.

## Agent behavior

1. Start with `lachesis.scan` or `lachesis scan`.
2. Read the lead's location and evidence before suggesting a fix.
3. Treat empty, partial, timed-out, or uncovered results as incomplete analysis—not “safe”.
4. Ask for `explain`/evidence around a lead before making a security claim.
5. Reuse one `Analysis` session for follow-up questions; do not rebuild the graph per query.

The public top-level names are intentionally small: `scan`, `Analysis`, `LeadSet`, `Deadline`,
and `AnalysisError`. Advanced graph primitives live under `lachesis.graph`.
