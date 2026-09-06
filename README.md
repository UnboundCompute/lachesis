<!-- mcp-name: io.github.UnboundCompute/lachesis -->

# Lachesis

**Lachesis reads your code and builds a map of it. Then you can ask the map questions, like who calls this function, where does this value go, and can bad input reach a dangerous spot.**

It works on C, Python, and TypeScript/JavaScript, all in one map.

[![PyPI](https://img.shields.io/pypi/v/lachesis-cpg)](https://pypi.org/project/lachesis-cpg/)
[![Python](https://img.shields.io/pypi/pyversions/lachesis-cpg)](https://pypi.org/project/lachesis-cpg/)
[![CI](https://github.com/UnboundCompute/lachesis/actions/workflows/ci.yml/badge.svg)](https://github.com/UnboundCompute/lachesis/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)
[![MCP](https://img.shields.io/badge/MCP-server-1f6feb)](https://modelcontextprotocol.io)
[![Docker](https://img.shields.io/badge/ghcr.io-lachesis-2496ED?logo=docker&logoColor=white)](https://github.com/UnboundCompute/lachesis/pkgs/container/lachesis)
[![Glama](https://glama.ai/mcp/servers/UnboundCompute/lachesis/badges/score.svg)](https://glama.ai/mcp/servers/UnboundCompute/lachesis)
[![Security Scan](https://img.shields.io/badge/security-Lachesis-8250df)](https://github.com/UnboundCompute/lachesis-action)

## What is this?

Search tools like grep tell you *where a word shows up* in your code. Lachesis is
different. It follows the actual data. It can tell you where a value came from,
where it goes next, and whether a request from the outside can reach something
dangerous, like a database call with no login check in front of it.

To do this it reads your code the same way a compiler does, not by guessing with
text patterns. So it doesn't miss a call just because a name was renamed or
imported in a weird way.

You can use it three ways: as a command in your terminal, as a Python library, or
as an [MCP](https://modelcontextprotocol.io) server that an AI agent can talk to.

## Quick start

Install it, then point it at a folder:

```bash
python -m pip install lachesis-cpg
lachesis ./my-project
```

It builds the map, saves it, and prints the **leads**. A lead is a spot where
outside input can reach something sensitive with no check in the way. Each lead is
a question to look into, not a final answer.

```
  ✓ compiling (0.7s)
  2,677 nodes, 4,539 edges from typescript-compiler-api
  ✓ finding entrypoints that reach sensitive effects (0.1s)

2 leads (lens=all)
  1. [0.810] handleWebhook (http/webhook.ts:10, route) -> findById(documentId) [database]
     a caller that passes no recognized guard can read or write data
     through findById(documentId) starting from handleWebhook
  2. [0.810] handleWebhook (http/webhook.ts:10, route) -> findById(invoiceId) [database]
     this function branches on something, but no login-style check is seen here
```

You can also give it a git URL instead of a folder:
`lachesis https://github.com/owner/repo`. It downloads the code to a temp folder,
scans it, and cleans up after.

The first scan of a project is slow. After that the map is cached under
`~/.lachesis/cache`, so every run after is fast.

## The three ways to use it

**Terminal.** One `lachesis` command. `lachesis ./repo` is the easy front door.
If you want more control, the steps map to three passes:

```bash
lachesis build   ./my-project graph.kuzu     # step 1: read the code, build the map
lachesis enrich  graph.kuzu                   # step 2: work out the data flow
lachesis analyze graph.kuzu --summary         # step 3: print the leads
lachesis explain graph.kuzu tree.c:1487       # show all the evidence for one spot
```

**Python library.** Open the map once, then ask it as many questions as you want.

```python
import lachesis

a = lachesis.Analysis.build("./my-project", "graph.kuzu", enrich=True)
leads = a.scan()
print(leads.summary())

print(a.explain_sink("tree.c", 1487))   # all the evidence for one spot
```

Runnable example scripts are in [`examples/`](./examples/README.md).

**MCP (for AI agents).** Start the server and an agent can build and query the map
on its own:

```bash
lachesis mcp ./my-project
```

See [MCP](#mcp) below for setup in Cursor, VS Code, Claude, and Docker.

## What you can ask

Once the map is built, these are the moves. They work from the terminal, the
Python library, or as MCP tools an agent uses:

| You want to know | The tool |
|---|---|
| What is this part of the code built around? | `hubs` |
| Where is this name? | `search` |
| Who calls this? What does it call? | `callers`, `callees` |
| Show me the real source | `read_body` |
| What's in this file or folder? | `open_file`, `open_folder` |
| Where does this value go? What feeds this spot? | `flow`, `sources_of` |
| Does this input reach that spot? | `reaches` (gives a path, or a clear no) |
| What does this pointer point at? | `points_to`, `aliases` |
| Where does outside input reach something dangerous? | `taint` |
| Is this C object freed twice, or used after it's freed? | the C lifetime pass |
| Which entrypoints reach sensitive spots with no check? | `scan` (the leads) |
| All the evidence for one spot, in one call | `explain` |

Every answer comes with how sure it is. Some links are exact. Some are a safe
guess, and Lachesis tells you when it's guessing instead of hiding it. Read the
answers as evidence, not as a verdict.

## MCP

Run `lachesis mcp` from the same place you built the map. You can hand it a
`graph.kuzu` path, but you don't have to. Start it with no argument and the agent
builds its own map when you point it at a repo.

**One click** (uses `uvx`, no install step):

[![Add lachesis to Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/install-mcp?name=lachesis&config=eyJjb21tYW5kIjoidXZ4IiwiYXJncyI6WyItLWZyb20iLCJsYWNoZXNpcy1jcGciLCJsYWNoZXNpcyIsIm1jcCJdfQ==)
&nbsp;
[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Lachesis-0098FF?logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=lachesis&config=%7B%22command%22%3A%22uvx%22%2C%22args%22%3A%5B%22--from%22%2C%22lachesis-cpg%22%2C%22lachesis%22%2C%22mcp%22%5D%7D)

Or set it up by hand. If the package is already installed:

```json
{
  "mcpServers": {
    "lachesis": { "command": "lachesis", "args": ["mcp"] }
  }
}
```

Or let `uvx` fetch it on first run, no install:

```json
{
  "mcpServers": {
    "lachesis": { "command": "uvx", "args": ["--from", "lachesis-cpg", "lachesis", "mcp"] }
  }
}
```

Or run it in Docker, with all three languages already in the image:

```json
{
  "mcpServers": {
    "lachesis": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "-v", "/path/to/your/project:/src",
               "ghcr.io/unboundcompute/lachesis:edge"]
    }
  }
}
```

More client notes are in [`docs/queries.md`](./docs/queries.md#the-lachesis-mcp-server).

## Languages

Each language is read by a real compiler or its own parser, never a text guess.

| Language | Read with | File types |
|---|---|---|
| TypeScript / JavaScript | the TypeScript compiler | `.ts` `.tsx` `.mts` `.cts` `.js` `.jsx` |
| Python | Python's own `ast` + `symtable` | `.py` `.pyi` |
| C | Clang | `.c` `.h` |

A mixed project is **one map, not three**. A Python function and a TypeScript
function it calls sit in the same map, and the same tools work across both.

Two limits worth knowing. Python has no type checker, so it matches attribute
calls by name. C reads one file at a time, so it won't follow a call through a
function-pointer table it never sees. Each language says what it can and can't do.

## How it works

Lachesis works in three steps, and each one is a command.

1. **build**: read the code with real compilers into a plain map of symbols and
   calls. This is the fast part, and it's all most navigation needs.
2. **enrich**: work out how data flows through the map. This isn't done at build
   time. A question only computes the part of the flow it needs, then caches it.
3. **analyze**: run over the map and print the leads. These are sensitive spots,
   scored and matched to known bug shapes. It has a time limit, so a big project
   can't hang.

There's also a **C lifetime pass**. Some bugs, like freeing the same object twice
or using it after it's freed, aren't about one spot. They're about the whole life
of an object. A separate pass tracks each C object being allocated, freed, and
used, and reports double-free and use-after-free with a path showing how it
happens.

The map is saved as a folder (`graph.kuzu`). It holds an embedded database plus a
small index file. That folder *is* the map. Every tool reads it directly.

More detail is in [`docs/graph-model.md`](./docs/graph-model.md) (what's in the
map) and [`docs/scaling.md`](./docs/scaling.md) (big repos, memory, and speed).

## Install

```bash
python -m pip install lachesis-cpg
```

Works on Python 3.10–3.12. Python analysis needs nothing extra. Scanning
TypeScript/JavaScript needs `node` on your PATH, and C needs `clang`. If one is
missing you get a clear message, not a crash.

To work from a clone (for contributors):

```bash
git clone https://github.com/UnboundCompute/lachesis && cd lachesis
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
npm ci
cargo build --release --manifest-path native/clang_frontend/Cargo.toml
```

## Where to go next

- [`examples/`](./examples/README.md): a five-minute walkthrough plus a runnable script per feature.
- [`docs/graph-model.md`](./docs/graph-model.md): what's in the map.
- [`docs/queries.md`](./docs/queries.md): every way to ask a question.
- [`docs/scaling.md`](./docs/scaling.md): big repos, memory, and CI.

## Roadmap

Done recently:

- [x] **C lifetime bugs.** Finds double-free and use-after-free on C objects, with a path showing how, and no false alarms on the clean paths.
- [x] **Big repos.** Large multi-language trees build in parallel pieces and link into one map, staying inside a set memory budget.
- [x] **Scan a git URL directly.** Point it at `https://…`, it downloads, scans, and cleans up.
- [x] **One tool, three front doors.** The same code powers the terminal command, the Python library, and the MCP tools.

Coming next:

- [ ] **C lifetime bugs across functions**: free in one function, use in another.
- [ ] **A single "can this input reach this spot?" question** that returns a path or a clear no, across files and languages.

## Status

Lachesis is early and moving fast. The map, the storage, the navigation and MCP
tools, and the C lifetime pass all work today and are checked by a test suite. The
lifetime pass is C-only for now and works within one function. One known false
alarm is tracked. The tools may still change before 1.0; the
[`CHANGELOG`](./CHANGELOG.md) lists changes.

## License

AGPL-3.0. See [`LICENSE`](./LICENSE). You can use, study, change, and share it,
including for commercial use. If you run a changed version as a network service,
you have to share your changed source with its users. If that doesn't fit your
case, a separate commercial license may be an option. See
[`CONTRIBUTING.md`](./CONTRIBUTING.md) or open an issue.

## Security

Found a security bug? Please don't open a public issue. See
[`SECURITY.md`](./SECURITY.md) for how to report it privately.
