#!/usr/bin/env node
/**
 * Worker-thread launcher for the TypeScript-Compiler-API graph frontend.
 *
 * Usage:
 *   node lachesis/frontends/typescript/build_graph.mjs SRC_DIR [OUT_DIR]
 *
 * Why this indirection exists
 * ---------------------------
 * The real work lives in build_graph_impl.mjs, which descends the TypeScript AST
 * recursively (`ts.forEachChild`). Over large monorepo scopes with deeply nested
 * types/JSX that descent can exceed the native call-stack and SIGABRT the whole
 * process before any graph is produced.
 *
 * On Linux the frontend child raises RLIMIT_STACK (core/runner.py) so the main
 * thread gets a large OS-backed stack and the raised V8 `--stack-size` unwinds
 * safely. On macOS the *main thread* stack is pinned at 8 MiB regardless of
 * RLIMIT_STACK, so `--stack-size` cannot help there and the parse still aborts.
 *
 * A worker thread's stack, by contrast, is sized at creation via
 * `resourceLimits.stackSizeMb` and is not subject to the macOS main-thread pin.
 * So this launcher does nothing but re-run the implementation on a worker with a
 * large stack, forwarding argv and propagating the exit status. The heavy code
 * is untouched; only the thread it runs on changes.
 *
 * The heap and stack ceilings the main process received as V8 CLI flags
 * (`--max-old-space-size`, `--stack-size`) cannot simply be forwarded as the
 * worker's execArgv: Node rejects `--max-old-space-size` there
 * (ERR_WORKER_INVALID_EXEC_ARGV), and inheriting `--stack-size` would clamp the
 * worker isolate's V8 stack back to the small main-thread value and defeat the
 * point. So the worker starts with an empty execArgv and the two ceilings are
 * re-expressed as worker resourceLimits instead: the heap cap becomes
 * maxOldGenerationSizeMb, and the stack becomes stackSizeMb (large, from the OS
 * thread stack, so V8 derives a correspondingly large stack limit).
 */
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Worker, isMainThread } from "node:worker_threads";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const implementation = path.join(scriptDir, "build_graph_impl.mjs");

function workerStackMb() {
  // A worker's default stack is only ~4 MiB (smaller than the main thread), so
  // this must be set explicitly and generously. 200 MiB of address space is
  // committed lazily to the recursion depth actually used, so it is cheap until
  // needed and still leaves ample room under the process memory budget.
  const raw = process.env.LACHESIS_TS_WORKER_STACK_MB;
  const parsed = raw === undefined ? NaN : Number.parseInt(raw, 10);
  const value = Number.isFinite(parsed) ? parsed : 200;
  return Math.max(8, value);
}

function flagValueMb(name) {
  // Recover a `--flag=NN` megabyte value the main process was launched with, so
  // it can be re-expressed as a worker resourceLimit.
  const prefix = `${name}=`;
  for (const flag of process.execArgv) {
    if (flag.startsWith(prefix)) {
      const value = Number.parseInt(flag.slice(prefix.length), 10);
      if (Number.isFinite(value)) return value;
    }
  }
  return undefined;
}

if (isMainThread) {
  const resourceLimits = { stackSizeMb: workerStackMb() };
  const oldSpaceMb = flagValueMb("--max-old-space-size");
  if (oldSpaceMb !== undefined) resourceLimits.maxOldGenerationSizeMb = oldSpaceMb;
  const worker = new Worker(implementation, {
    argv: process.argv.slice(2),
    execArgv: [],
    resourceLimits,
  });
  worker.on("error", (error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  });
  worker.on("exit", (code) => {
    // A worker that ended via process.exit(code) reports that code; a clean
    // fall-off-the-end reports 0. Mirror it so the Python runner sees the same
    // status it would have seen running the implementation directly.
    if (code !== 0 && !process.exitCode) process.exitCode = code;
  });
} else {
  // Defensive: if this file is ever itself loaded on a worker, run the impl
  // in-place rather than spawning another nested worker.
  await import(implementation);
}
