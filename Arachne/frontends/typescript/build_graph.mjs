#!/usr/bin/env node
/**
 * Standalone TypeScript-Compiler-API graph prototype.
 *
 * This intentionally does not import or modify Arachne. It tests whether the
 * compiler can provide the precise low-level facts while preserving Arachne's
 * five-tier, LLM-drillable shape.
 *
 * Usage:
 *   node Arachne/frontends/typescript/build_graph.mjs [SRC_DIR] [OUT_DIR]
 *
 * TypeScript lookup order:
 *   1. TYPESCRIPT_PATH=/path/to/typescript (package directory or JS entrypoint)
 *   2. a normal local `typescript` dependency
 *   3. the existing raven4/nereus TypeScript frontend dependency
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const scriptDir = path.dirname(fileURLToPath(import.meta.url));

function loadTypeScript() {
  const candidates = [];
  if (process.env.TYPESCRIPT_PATH) candidates.push(process.env.TYPESCRIPT_PATH);
  candidates.push("typescript");
  candidates.push(
    path.resolve(scriptDir, "../../../../nereus/v3/ts_frontend/node_modules/typescript"),
  );
  const failures = [];
  for (const candidate of candidates) {
    try {
      return { ts: require(candidate), loadedFrom: candidate };
    } catch (error) {
      failures.push(`${candidate}: ${error.code || error.message}`);
    }
  }
  throw new Error(
    "Unable to load TypeScript. Install it locally or set TYPESCRIPT_PATH.\n" +
      failures.join("\n"),
  );
}

const { ts, loadedFrom } = loadTypeScript();
const FRONTEND_ID = "typescript-compiler-api";
const CONTRACT_VERSION = 2;
const sourceDir = path.resolve(process.argv[2] || "src");
const outputDir = path.resolve(
  process.argv[3] || "graph_out/compiler_layered",
);

const SUPPORTED = new Set([".ts", ".tsx", ".js", ".jsx", ".mts", ".cts"]);
const IGNORED_DIRS = new Set([".git", "node_modules", "graph_out", "dist", "build"]);
const TIER_NAMES = {
  T0: "perimeter",
  T1: "reachability",
  T2: "path",
  T3: "body",
  T4: "proof",
};
const TIER_ORDER = ["T0", "T1", "T2", "T3", "T4"];
const ASSIGNMENT_KINDS = new Set([
  ts.SyntaxKind.EqualsToken,
  ts.SyntaxKind.PlusEqualsToken,
  ts.SyntaxKind.MinusEqualsToken,
  ts.SyntaxKind.AsteriskEqualsToken,
  ts.SyntaxKind.SlashEqualsToken,
  ts.SyntaxKind.PercentEqualsToken,
  ts.SyntaxKind.AmpersandEqualsToken,
  ts.SyntaxKind.BarEqualsToken,
  ts.SyntaxKind.CaretEqualsToken,
  ts.SyntaxKind.LessThanLessThanEqualsToken,
  ts.SyntaxKind.GreaterThanGreaterThanEqualsToken,
  ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken,
  ts.SyntaxKind.AsteriskAsteriskEqualsToken,
  ts.SyntaxKind.AmpersandAmpersandEqualsToken,
  ts.SyntaxKind.BarBarEqualsToken,
  ts.SyntaxKind.QuestionQuestionEqualsToken,
]);
const SINK_NAMES = new Map([
  ["eval", "dynamic-code"],
  ["Function", "dynamic-code"],
  ["fetch", "network"],
  ["exec", "process"],
  ["execFile", "process"],
  ["spawn", "process"],
  ["writeFile", "filesystem-write"],
  ["writeFileSync", "filesystem-write"],
  ["query", "database"],
  ["execute", "database"],
  ["findById", "database"],
  ["findOne", "database"],
  ["send", "response"],
  ["json", "response"],
  ["redirect", "response"],
]);

function walk(directory) {
  const result = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && IGNORED_DIRS.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) result.push(...walk(absolute));
    else if (entry.isFile() && SUPPORTED.has(path.extname(entry.name))) {
      result.push(path.resolve(absolute));
    }
  }
  return result.sort();
}

function digest(...parts) {
  return crypto.createHash("sha256").update(parts.join(":"), "utf8").digest("hex").slice(0, 16);
}

const legacyIdsByV2 = new Map();
function stableId(kind, ...parts) {
  const legacyId = `${kind}:${digest(kind, ...parts)}`;
  const raw = parts.map((part) => String(part)).join("\u0000");
  const identityDigest = crypto.createHash("sha256").update(
    `v2\u0000frontend\u0000${FRONTEND_ID}\u0000${kind}\u0000${raw}`,
    "utf8",
  ).digest("hex").slice(0, 20);
  const id = `v2:frontend:${FRONTEND_ID}:${kind}:${identityDigest}`;
  legacyIdsByV2.set(id, legacyId);
  return id;
}

function normalize(fileName) {
  return path.resolve(fileName);
}

function relative(fileName) {
  const value = path.relative(sourceDir, normalize(fileName));
  return value.startsWith("..") ? normalize(fileName) : value || path.basename(fileName);
}

function compact(text, limit = 240) {
  let value = "";
  let pendingSpace = false;
  for (const character of String(text || "").trim()) {
    if (character.trim() === "") {
      pendingSpace = Boolean(value);
    } else {
      if (pendingSpace) value += " ";
      value += character;
      pendingSpace = false;
    }
  }
  return value.length > limit ? `${value.slice(0, limit - 1)}…` : value;
}

const contentHashes = new Map();
function languageForFile(fileName) {
  const extension = path.extname(fileName).toLowerCase();
  return extension === ".js" || extension === ".jsx" ? "javascript" : "typescript";
}

function contentHash(fileName) {
  const absolute = normalize(fileName);
  if (!contentHashes.has(absolute)) {
    let contents = "";
    try { contents = fs.readFileSync(absolute); } catch { /* diagnostics can lack source files */ }
    contentHashes.set(
      absolute,
      crypto.createHash("sha256").update(contents).digest("hex"),
    );
  }
  return contentHashes.get(absolute);
}

function jsonKey(value) {
  if (Array.isArray(value)) return `[${value.map(jsonKey).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jsonKey(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function compilerOptions() {
  const defaults = {
    allowJs: true,
    checkJs: false,
    noEmit: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    jsx: ts.JsxEmit.Preserve,
    allowSyntheticDefaultImports: true,
    esModuleInterop: true,
    experimentalDecorators: true,
  };
  const configPath = ts.findConfigFile(sourceDir, ts.sys.fileExists, "tsconfig.json");
  if (!configPath) return { options: defaults, configPath: null, configErrors: [] };
  const loaded = ts.readConfigFile(configPath, ts.sys.readFile);
  if (loaded.error) return { options: defaults, configPath, configErrors: [loaded.error] };
  const parsed = ts.parseJsonConfigFileContent(
    loaded.config,
    ts.sys,
    path.dirname(configPath),
    defaults,
    configPath,
  );
  return {
    options: { ...parsed.options, ...defaults },
    configPath,
    configErrors: parsed.errors || [],
  };
}

const applicationRootNames = walk(sourceDir);
if (!applicationRootNames.length) throw new Error(`No TypeScript/JavaScript files found under ${sourceDir}`);
const rootSet = new Set(applicationRootNames.map(normalize));
const config = compilerOptions();
const configuredDependencyLimit = Number.parseInt(
  process.env.ARACHNE_MAX_DEPENDENCY_FILES || "500", 10,
);
const dependencyLimit = Number.isFinite(configuredDependencyLimit) && configuredDependencyLimit >= 0
  ? configuredDependencyLimit : 500;

function sourceSpecifiers(fileName) {
  let text;
  try { text = fs.readFileSync(fileName, "utf8"); } catch { return []; }
  const kind = fileName.endsWith(".tsx") ? ts.ScriptKind.TSX :
    fileName.endsWith(".jsx") ? ts.ScriptKind.JSX :
    fileName.endsWith(".js") ? ts.ScriptKind.JS : ts.ScriptKind.TS;
  const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, kind);
  const result = [];
  const visit = (node) => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
        node.moduleSpecifier && ts.isStringLiteralLike(node.moduleSpecifier)) {
      result.push(node.moduleSpecifier.text);
    } else if (ts.isCallExpression(node) && node.arguments.length &&
        ts.isStringLiteralLike(node.arguments[0]) &&
        ((ts.isIdentifier(node.expression) && node.expression.text === "require") ||
         node.expression.kind === ts.SyntaxKind.ImportKeyword)) {
      result.push(node.arguments[0].text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return [...new Set(result)];
}

function runtimeResolution(containingFile, specifier) {
  if (specifier.startsWith("node:") || ts.sys.getExecutingFilePath() === specifier) return null;
  try {
    const resolved = createRequire(containingFile).resolve(specifier);
    if (!path.isAbsolute(resolved) || resolved.endsWith(".d.ts")) return null;
    return SUPPORTED.has(path.extname(resolved)) ? normalize(resolved) : null;
  } catch {
    return null;
  }
}

function discoverRuntimeDependencies(entries) {
  const discovered = new Set();
  const queue = [...entries];
  const visited = new Set(entries.map(normalize));
  while (queue.length && discovered.size < dependencyLimit) {
    const containingFile = queue.shift();
    for (const specifier of sourceSpecifiers(containingFile)) {
      const resolved = runtimeResolution(containingFile, specifier);
      if (!resolved || rootSet.has(resolved) || visited.has(resolved)) continue;
      visited.add(resolved);
      discovered.add(resolved);
      queue.push(resolved);
      if (discovered.size >= dependencyLimit) break;
    }
  }
  return [...discovered].sort();
}

const runtimeDependencyNames = discoverRuntimeDependencies(applicationRootNames);
const compilerRootNames = [...new Set([...applicationRootNames, ...runtimeDependencyNames])];
const compilerRootSet = new Set(compilerRootNames.map(normalize));
const program = ts.createProgram({ rootNames: compilerRootNames, options: config.options });
const checker = program.getTypeChecker();
const compilerRootSources = compilerRootNames
  .map((fileName) => program.getSourceFile(fileName))
  .filter(Boolean);
const remainingDependencyCapacity = Math.max(
  0, dependencyLimit - runtimeDependencyNames.length,
);
const declarationDependencies = program.getSourceFiles()
  .filter((sf) => !compilerRootSet.has(normalize(sf.fileName)) &&
    !program.isSourceFileDefaultLibrary(sf) && Boolean(packageIdentity(sf.fileName)))
  .sort((left, right) => normalize(left.fileName).localeCompare(normalize(right.fileName)))
  .slice(0, remainingDependencyCapacity);
const analysisSourceFiles = [...new Map(
  [...compilerRootSources, ...declarationDependencies]
    .map((sf) => [normalize(sf.fileName), sf]),
).values()].sort((left, right) =>
  normalize(left.fileName).localeCompare(normalize(right.fileName)),
);
const analysisFileNames = analysisSourceFiles.map((sf) => normalize(sf.fileName));

const nodes = new Map();
const edges = [];
const edgeKeys = new Set();
const tierNodes = new Map(TIER_ORDER.map((tier) => [tier, new Set()]));
const sourceFileIds = new Map();
const entityByDeclaration = new Map();
const valueByDeclaration = new Map();
const bodyByNode = new Map();
const pathByNode = new Map();
const proofByNode = new Map();
const functionStackByNode = new Map();
const moduleExportNames = new Map();
const packageIds = new Map();
const scopeByNode = new Map();
const scopeKinds = new Map();
const moduleScopeIds = new Map();
const lexicalSymbols = [];
const symbolIdsByTarget = new Map();
const typeParameterIdsByDeclaration = new Map();
const definitionHistoryByTarget = new Map();
const definitionByDeclaration = new Map();
const propertyPathIds = new Map();

function packageIdentity(fileName) {
  const absolute = normalize(fileName);
  const marker = `${path.sep}node_modules${path.sep}`;
  const index = absolute.lastIndexOf(marker);
  if (index < 0) return null;
  const remainder = absolute.slice(index + marker.length).split(path.sep);
  if (!remainder.length) return null;
  return remainder[0].startsWith("@") && remainder.length > 1
    ? `${remainder[0]}/${remainder[1]}`
    : remainder[0];
}

function packageRoot(fileName) {
  const absolute = normalize(fileName);
  const marker = `${path.sep}node_modules${path.sep}`;
  const index = absolute.lastIndexOf(marker);
  if (index < 0) return null;
  const prefix = absolute.slice(0, index + marker.length);
  const remainder = absolute.slice(index + marker.length).split(path.sep);
  const pieces = remainder[0]?.startsWith("@") ? remainder.slice(0, 2) : remainder.slice(0, 1);
  return pieces.length ? path.join(prefix, ...pieces) : null;
}

function ensurePackage(fileName, packageName) {
  if (!packageName) return null;
  const root = packageRoot(fileName);
  const identity = root || packageName;
  if (packageIds.has(identity)) return packageIds.get(identity);
  let metadata = {};
  if (root) {
    try {
      const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
      metadata = {
        version: packageJson.version || null,
        package_type: packageJson.type || null,
        keywords: Array.isArray(packageJson.keywords) ? packageJson.keywords : [],
      };
    } catch { /* compiler declarations can live in packages without metadata */ }
  }
  const id = stableId("package", identity);
  addNode("T0", id, "package", packageName, {
    package_name: packageName, package_root: root, provenance: "dependency",
    ...metadata,
  });
  packageIds.set(identity, id);
  return id;
}

function sourceProvenance(fileName) {
  const absolute = normalize(fileName);
  if (rootSet.has(absolute)) return { provenance: "application", package_name: null };
  if (program.isSourceFileDefaultLibrary(program.getSourceFile(absolute))) {
    return { provenance: "standard-library", package_name: "typescript" };
  }
  const packageName = packageIdentity(absolute);
  if (packageName) return { provenance: "dependency", package_name: packageName };
  return { provenance: "workspace-library", package_name: null };
}

function ensureSourceFile(sourceFile, includedBecause = "project-root") {
  if (!sourceFile) return null;
  const absolute = normalize(sourceFile.fileName);
  if (sourceFileIds.has(absolute)) return sourceFileIds.get(absolute);
  const id = stableId("file", absolute);
  const provenance = sourceProvenance(absolute);
  addNode("T0", id, "file", relative(absolute), {
    file: relative(absolute),
    absolute_file: absolute,
    content_hash: crypto.createHash("sha256").update(sourceFile.text).digest("hex"),
    lines: sourceFile.getLineAndCharacterOfPosition(sourceFile.end).line + 1,
    language_variant: ts.LanguageVariant[sourceFile.languageVariant],
    script_kind: ts.ScriptKind[sourceFile.scriptKind],
    ...provenance,
    included_because: includedBecause,
    declaration_file: sourceFile.isDeclarationFile,
  });
  sourceFileIds.set(absolute, id);
  const packageId = ensurePackage(absolute, provenance.package_name);
  if (packageId) addEdge("PACKAGE_CONTAINS", packageId, id);
  return id;
}

function addNode(tier, id, kind, label, properties = {}) {
  const absoluteFile = properties.absolute_file
    ? normalize(properties.absolute_file) : null;
  const canonicalProperties = {
    fact_origin: "compiler",
    confidence: "exact",
    evidence_ids: [],
    legacy_id: legacyIdsByV2.get(id) || null,
    ...properties,
  };
  if (absoluteFile) Object.assign(canonicalProperties, {
    frontend_id: FRONTEND_ID,
    language: languageForFile(absoluteFile),
    absolute_file: absoluteFile,
    content_hash: canonicalProperties.content_hash || contentHash(absoluteFile),
    compiler_node_id: canonicalProperties.compiler_node_id ||
      legacyIdsByV2.get(id) || id,
  });
  if (!nodes.has(id)) {
    nodes.set(id, { id, kind, label, properties: canonicalProperties, tier });
    tierNodes.get(tier).add(id);
  } else {
    Object.assign(nodes.get(id).properties, canonicalProperties);
  }
  return id;
}

function addEdge(kind, source, target, properties = {}) {
  if (!source || !target || source === target) return;
  const canonicalProperties = {
    fact_origin: "compiler", confidence: "exact", evidence_ids: [], ...properties,
  };
  const key = `${kind}|${source}|${target}|${jsonKey(canonicalProperties)}`;
  if (edgeKeys.has(key)) return;
  edgeKeys.add(key);
  edges.push({ kind, source, target, properties: canonicalProperties });
}

function sourcePosition(node) {
  const sf = node.getSourceFile();
  const start = node.getStart(sf, false);
  const end = node.getEnd();
  const begin = sf.getLineAndCharacterOfPosition(start);
  const finish = sf.getLineAndCharacterOfPosition(Math.max(start, end - 1));
  return {
    file: relative(sf.fileName),
    absolute_file: normalize(sf.fileName),
    start_offset: start,
    end_offset: end,
    start_line: begin.line + 1,
    start_column: begin.character + 1,
    end_line: finish.line + 1,
    end_column: finish.character + 1,
  };
}

function nodeKey(node, suffix = "") {
  const sf = node.getSourceFile();
  return [normalize(sf.fileName), node.getStart(sf, false), node.getEnd(), suffix];
}

function safeType(node) {
  try {
    return compact(checker.typeToString(
      checker.getTypeAtLocation(node),
      node,
      ts.TypeFormatFlags.NoTruncation | ts.TypeFormatFlags.UseAliasDefinedOutsideCurrentScope,
    ), 500);
  } catch {
    return "unknown";
  }
}

function typeFlagNames(type) {
  return Object.entries(ts.TypeFlags)
    .filter(([name, value]) =>
      typeof value === "number" && value > 0 && (value & (value - 1)) === 0 &&
      (type.flags & value) !== 0 && !Number.isInteger(Number(name)),
    )
    .map(([name]) => name)
    .sort();
}

function typeMetadata(node) {
  if (!node) return null;
  try {
    const type = checker.getTypeAtLocation(node);
    const unionTypes = type.isUnion?.() ? type.types.map((item) => safeTypeFromType(item, node)) : [];
    const intersectionTypes = type.isIntersection?.()
      ? type.types.map((item) => safeTypeFromType(item, node)) : [];
    let typeArguments = [];
    if ((type.flags & ts.TypeFlags.Object) &&
        (type.objectFlags & ts.ObjectFlags.Reference)) {
      typeArguments = checker.getTypeArguments(type)
        .map((item) => safeTypeFromType(item, node));
    }
    return {
      text: safeTypeFromType(type, node),
      flags: typeFlagNames(type),
      symbol: type.aliasSymbol?.getName?.() || type.getSymbol?.()?.getName?.() || null,
      union_types: unionTypes,
      intersection_types: intersectionTypes,
      type_arguments: typeArguments,
      nullable: Boolean(type.flags & (ts.TypeFlags.Null | ts.TypeFlags.Undefined)),
      literal: Boolean(type.flags & ts.TypeFlags.Literal),
    };
  } catch {
    return { text: "unknown", flags: [], union_types: [], intersection_types: [],
      type_arguments: [], nullable: false, literal: false };
  }
}

function safeTypeFromType(type, location) {
  try {
    return compact(checker.typeToString(
      type,
      location,
      ts.TypeFormatFlags.NoTruncation | ts.TypeFormatFlags.UseAliasDefinedOutsideCurrentScope,
    ), 500);
  } catch {
    return "unknown";
  }
}

function declaredTypeMetadata(node) {
  if (!ts.isIdentifier(node)) return null;
  try {
    let symbol = checker.getSymbolAtLocation(node);
    if (!symbol) return null;
    if (symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    const declaration = symbol.valueDeclaration || symbol.declarations?.[0];
    if (!declaration) return null;
    const type = checker.getTypeOfSymbolAtLocation(symbol, declaration);
    return {
      text: safeTypeFromType(type, declaration),
      declaration_file: normalize(declaration.getSourceFile().fileName),
      declaration_start_offset: declaration.getStart(declaration.getSourceFile(), false),
    };
  } catch {
    return null;
  }
}

function declarationTypeExtensions(node) {
  const typeParameters = [...(node.typeParameters || [])].map((parameter, position) => ({
    name: parameter.name.text,
    position,
    constraint: parameter.constraint ? safeType(parameter.constraint) : null,
    default: parameter.default ? safeType(parameter.default) : null,
  }));
  const heritage = [...(node.heritageClauses || [])].flatMap((clause) =>
    clause.types.map((heritageType) => ({
      relationship: clause.token === ts.SyntaxKind.ExtendsKeyword ? "extends" : "implements",
      expression: heritageType.expression.getText(node.getSourceFile()),
      type: safeType(heritageType),
      type_arguments: heritageType.typeArguments?.map((item) => safeType(item)) || [],
    })),
  );
  let overloads = [];
  if (node.name) {
    try {
      const symbol = checker.getSymbolAtLocation(node.name);
      overloads = (symbol?.declarations || [])
        .filter((declaration) => isFunctionEntity(declaration))
        .map((declaration) => {
          const signature = checker.getSignatureFromDeclaration(declaration);
          return {
            file: normalize(declaration.getSourceFile().fileName),
            start_offset: declaration.getStart(declaration.getSourceFile(), false),
            signature: signature ? checker.signatureToString(
              signature, declaration, ts.TypeFormatFlags.NoTruncation,
            ) : null,
            implementation: Boolean(declaration.body),
          };
        });
    } catch { /* anonymous/compiler-synthesized declarations have no symbol */ }
  }
  return { type_parameters: typeParameters, heritage, overloads };
}

function declarationTypePredicate(node) {
  if (!isFunctionEntity(node)) return null;
  try {
    const signature = checker.getSignatureFromDeclaration(node);
    const predicate = signature ? checker.getTypePredicateOfSignature(signature) : null;
    if (!predicate) return null;
    return {
      kind: ts.TypePredicateKind[predicate.kind],
      asserts: predicate.kind === ts.TypePredicateKind.AssertsIdentifier ||
        predicate.kind === ts.TypePredicateKind.AssertsThis,
      parameter: predicate.parameterName ||
        (predicate.kind === ts.TypePredicateKind.This ||
         predicate.kind === ts.TypePredicateKind.AssertsThis ? "this" : null),
      parameter_index: predicate.parameterIndex,
      type: predicate.type ? safeTypeFromType(predicate.type, node) : "truthy",
    };
  } catch {
    return null;
  }
}

function declarationMemberName(member) {
  if (!member.name) return null;
  if (ts.isIdentifier(member.name) || ts.isPrivateIdentifier(member.name) ||
      ts.isStringLiteralLike(member.name) || ts.isNumericLiteral(member.name)) {
    return member.name.text;
  }
  if (ts.isComputedPropertyName(member.name)) {
    return `[${compact(member.name.expression.getText(member.getSourceFile()), 120)}]`;
  }
  return compact(member.name.getText(member.getSourceFile()), 120);
}

function directTypeMembers(node) {
  let members = node.members ? [...node.members] : [];
  if (ts.isTypeAliasDeclaration(node) && ts.isTypeLiteralNode(node.type)) {
    members = [...node.type.members];
  }
  return members.map((member) => ({
    name: declarationMemberName(member),
    optional: Boolean(member.questionToken),
    readonly: hasModifier(member, ts.SyntaxKind.ReadonlyKeyword),
    kind: ts.SyntaxKind[member.kind],
    type: member.name ? safeType(member.name) : safeType(member),
  })).filter((member) => member.name);
}

function typeDeclarationProperties(node, extensions) {
  const heritage = extensions.heritage || [];
  const result = {
    members: directTypeMembers(node),
    extends: heritage.filter((item) => item.relationship === "extends")
      .map((item) => item.type),
    implements: heritage.filter((item) => item.relationship === "implements")
      .map((item) => item.type),
  };
  if (ts.isTypeAliasDeclaration(node)) {
    Object.assign(result, {
      alias_expression: compact(node.type.getText(node.getSourceFile()), 1000),
      union_members: ts.isUnionTypeNode(node.type)
        ? node.type.types.map((item) => compact(item.getText(node.getSourceFile()), 300)) : [],
      conditional: ts.isConditionalTypeNode(node.type),
      mapped: ts.isMappedTypeNode(node.type),
    });
  }
  return result;
}

function registerTypeParameters(node, ownerId) {
  const result = [];
  for (const [positionIndex, parameter] of [...(node.typeParameters || [])].entries()) {
    const position = sourcePosition(parameter);
    const id = stableId(
      "type-parameter", ...nodeKey(parameter, `${ownerId}:${positionIndex}:${parameter.name.text}`),
    );
    addNode("T2", id, "type-parameter", parameter.name.text, {
      ...position,
      owner_id: ownerId,
      position: positionIndex,
      constraint: parameter.constraint
        ? compact(parameter.constraint.getText(parameter.getSourceFile()), 500) : null,
      default: parameter.default
        ? compact(parameter.default.getText(parameter.getSourceFile()), 500) : null,
      type: safeType(parameter.name),
      frontend_extensions: {
        typescript: { syntax_kind: ts.SyntaxKind[parameter.kind] },
      },
    });
    addEdge("HAS_TYPE_PARAMETER", ownerId, id, { position: positionIndex });
    typeParameterIdsByDeclaration.set(parameter, id);
    result.push(id);
  }
  return result;
}

function literalValue(node) {
  if (!node) return { literal: false, value: null };
  if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node)) {
    return { literal: true, value: node.text };
  }
  if (node.kind === ts.SyntaxKind.TrueKeyword) return { literal: true, value: true };
  if (node.kind === ts.SyntaxKind.FalseKeyword) return { literal: true, value: false };
  if (node.kind === ts.SyntaxKind.NullKeyword) return { literal: true, value: null };
  if (ts.isNoSubstitutionTemplateLiteral(node)) return { literal: true, value: node.text };
  return { literal: false, value: null };
}

function decoratorName(expression) {
  let current = expression;
  if (ts.isCallExpression(current)) current = current.expression;
  if (ts.isIdentifier(current)) return current.text;
  if (ts.isPropertyAccessExpression(current)) return current.name.text;
  return compact(current.getText(current.getSourceFile()), 120);
}

function registerDecorators(node, targetId) {
  if (!ts.canHaveDecorators(node)) return [];
  const decorators = ts.getDecorators(node) || [];
  const ids = [];
  decorators.forEach((decorator, decoratorIndex) => {
    const expression = decorator.expression;
    const call = ts.isCallExpression(expression) ? expression : null;
    const position = sourcePosition(decorator);
    const name = decoratorName(expression);
    const id = stableId("decorator", ...nodeKey(decorator, `${targetId}:${decoratorIndex}:${name}`));
    const argumentsData = (call?.arguments || []).map((argument, argumentIndex) => ({
      position: argumentIndex,
      expression: compact(argument.getText(argument.getSourceFile()), 240),
      type: safeType(argument),
      ...literalValue(argument),
    }));
    addNode("T2", id, "decorator", name, {
      ...position,
      target_id: targetId,
      expression: compact(expression.getText(expression.getSourceFile()), 300),
      arguments: argumentsData,
      frontend_extensions: {
        typescript: { syntax_kind: ts.SyntaxKind[decorator.kind] },
      },
    });
    addEdge("DECORATES", id, targetId);
    argumentsData.forEach((argument) => addEdge("DECORATOR_ARGUMENT", id, targetId, {
      position: argument.position,
      expression: argument.expression,
      literal: argument.literal,
      value: argument.value,
    }));
    ids.push(id);
  });
  return ids;
}

function declarationName(node) {
  if (node.name && ts.isIdentifier(node.name)) return node.name.text;
  if (node.name && ts.isStringLiteralLike(node.name)) return node.name.text;
  if (node.name && ts.isComputedPropertyName(node.name)) return `[${compact(node.name.expression.getText(), 80)}]`;
  if ((ts.isArrowFunction(node) || ts.isFunctionExpression(node)) && ts.isVariableDeclaration(node.parent)) {
    return node.parent.name.getText();
  }
  if ((ts.isArrowFunction(node) || ts.isFunctionExpression(node)) && ts.isPropertyAssignment(node.parent)) {
    return node.parent.name.getText();
  }
  if (ts.isConstructorDeclaration(node)) return "constructor";
  return `<anonymous@${sourcePosition(node).start_line}>`;
}

function entityKind(node) {
  if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) return "class";
  if (ts.isInterfaceDeclaration(node)) return "interface";
  if (ts.isTypeAliasDeclaration(node)) return "type";
  if (ts.isEnumDeclaration(node)) return "enum";
  if (ts.isModuleDeclaration(node)) return "module";
  if (ts.isMethodDeclaration(node) || ts.isMethodSignature(node)) return "method";
  if (ts.isConstructorDeclaration(node)) return "constructor";
  return "function";
}

function isFunctionEntity(node) {
  return ts.isFunctionLike(node) &&
    !ts.isFunctionTypeNode(node) &&
    !ts.isConstructorTypeNode(node) &&
    !ts.isCallSignatureDeclaration(node) &&
    !ts.isConstructSignatureDeclaration(node) &&
    !ts.isIndexSignatureDeclaration(node);
}

function hasModifier(node, kind) {
  return Boolean(node.modifiers?.some((modifier) => modifier.kind === kind));
}

function registerEntity(node, ownerId = null) {
  if (entityByDeclaration.has(node)) return entityByDeclaration.get(node);
  const kind = entityKind(node);
  const name = declarationName(node);
  const position = sourcePosition(node);
  const id = stableId(kind, ...nodeKey(node, name));
  const typeExtensions = declarationTypeExtensions(node);
  const declaredTypeProperties = ["class", "interface", "type", "enum"].includes(kind)
    ? typeDeclarationProperties(node, typeExtensions) : {};
  const signature = isFunctionEntity(node) ? (() => {
    try {
      const sig = checker.getSignatureFromDeclaration(node);
      return sig ? checker.signatureToString(sig, node, ts.TypeFormatFlags.NoTruncation) : null;
    } catch { return null; }
  })() : null;
  const parameterRange = isFunctionEntity(node) ? (() => {
    const sf = node.getSourceFile();
    const parameters = node.parameters || [];
    if (!parameters.length) {
      const headerEnd = node.body?.getStart(sf, false) || node.getEnd();
      const opening = sf.text.indexOf("(", node.getStart(sf, false));
      const closing = opening >= 0 ? sf.text.indexOf(")", opening + 1) : -1;
      return opening >= 0 && closing >= 0 && closing < headerEnd
        ? { start: opening, end: closing } : { start: null, end: null };
    }
    let start = parameters.pos;
    let end = parameters.end;
    if (start > 0 && sf.text[start - 1] === "(") start -= 1;
    if (sf.text[start] !== "(") {
      start = parameters[0].getStart(sf, false);
      end = parameters[parameters.length - 1].getEnd() - 1;
    }
    return { start, end };
  })() : { start: null, end: null };
  addNode("T1", id, kind, name, {
    ...position,
    ...sourceProvenance(position.absolute_file),
    syntax_kind: ts.SyntaxKind[node.kind],
    type: safeType(node),
    signature,
    async: hasModifier(node, ts.SyntaxKind.AsyncKeyword),
    exported: hasModifier(node, ts.SyntaxKind.ExportKeyword),
    default_export: hasModifier(node, ts.SyntaxKind.DefaultKeyword),
    abstract: hasModifier(node, ts.SyntaxKind.AbstractKeyword),
    form: ts.isArrowFunction(node) ? "arrow" :
      ts.isFunctionExpression(node) ? "function-expression" :
      ts.isMethodDeclaration(node) || ts.isMethodSignature(node) ? "method" :
      ts.isConstructorDeclaration(node) ? "constructor" : "function",
    body_start_offset: node.body ? node.body.getStart(node.getSourceFile(), false) : position.start_offset,
    owner_id: ownerId,
    parameters_start_offset: parameterRange.start,
    parameters_end_offset: parameterRange.end,
    type_predicate: declarationTypePredicate(node),
    ...declaredTypeProperties,
    frontend_extensions: {
      typescript: typeExtensions,
    },
  });
  entityByDeclaration.set(node, id);
  const typeParameterIds = registerTypeParameters(node, id);
  if (typeParameterIds.length) {
    nodes.get(id).properties.type_parameter_ids = typeParameterIds;
    typeExtensions.type_parameters.forEach((parameter, index) => {
      parameter.node_id = typeParameterIds[index];
    });
  }
  const decoratorIds = registerDecorators(node, id);
  if (decoratorIds.length) nodes.get(id).properties.decorator_ids = decoratorIds;
  const sfId = ensureSourceFile(node.getSourceFile(), "referenced-declaration");
  addEdge(ownerId ? "DECLARES_MEMBER" : "DECLARES", ownerId || sfId, id);
  return id;
}

function declarationForSymbol(symbol) {
  if (!symbol) return null;
  let resolved = symbol;
  if (resolved.flags & ts.SymbolFlags.Alias) {
    try { resolved = checker.getAliasedSymbol(resolved); } catch { /* unresolved alias */ }
  }
  return resolved.valueDeclaration || resolved.declarations?.[0] || null;
}

function entityForDeclaration(declaration) {
  if (!declaration) return null;
  if (entityByDeclaration.has(declaration)) return entityByDeclaration.get(declaration);
  if (isFunctionEntity(declaration) || ts.isClassDeclaration(declaration) ||
      ts.isInterfaceDeclaration(declaration) || ts.isTypeAliasDeclaration(declaration) ||
      ts.isEnumDeclaration(declaration) || ts.isModuleDeclaration(declaration)) {
    return registerEntity(declaration, ownerFunction(declaration.parent));
  }
  return valueForDeclaration(declaration);
}

function valueForDeclaration(declaration, explicitScopeId = null) {
  if (!declaration) return null;
  if (valueByDeclaration.has(declaration)) return valueByDeclaration.get(declaration);
  const sf = declaration.getSourceFile();
  const nameNode = declaration.name || declaration;
  const name = compact(nameNode.getText(sf), 120);
  const kind = ts.isParameter(declaration) ? "parameter" :
    ts.isPropertyDeclaration(declaration) || ts.isPropertySignature(declaration) ? "property" :
    ts.isBindingElement(declaration) ? "binding" : "variable";
  const id = stableId("value", ...nodeKey(declaration, name));
  const position = sourcePosition(declaration);
  const owningFunction = ownerFunction(declaration);
  const symbolKind = declarationSymbolKind(declaration);
  let parameter = declaration;
  while (parameter && !ts.isParameter(parameter) && !ts.isSourceFile(parameter)) {
    parameter = parameter.parent;
  }
  const parameterPosition = ts.isParameter(parameter)
    ? parameter.parent.parameters.indexOf(parameter) : null;
  let scopeId = explicitScopeId || nearestScope(declaration);
  if (symbolKind === "var") scopeId = nearestHoistScope(scopeId);
  addNode("T2", id, kind, name, {
    ...position,
    ...sourceProvenance(position.absolute_file),
    type: safeType(nameNode),
    declaration_kind: ts.SyntaxKind[declaration.kind],
    owner_function_id: owningFunction,
    scope_id: scopeId,
    symbol_kind: symbolKind,
    symbol_name: lexicalName(declaration),
    aggregate_binding: !ts.isIdentifier(nameNode),
    parameter_position: parameterPosition,
    roles: [],
  });
  valueByDeclaration.set(declaration, id);
  const decoratorIds = registerDecorators(declaration, id);
  if (decoratorIds.length) nodes.get(id).properties.decorator_ids = decoratorIds;
  addEdge("DECLARES_VALUE", owningFunction || sourceFileIds.get(normalize(sf.fileName)), id);
  if (ts.isIdentifier(nameNode) || ts.isPrivateIdentifier(nameNode)) {
    registerLexicalSymbol(
      id, lexicalName(declaration), symbolKind, scopeId, owningFunction,
      null, declaration,
    );
  }
  return id;
}

function ownerFunction(node) {
  let current = node;
  while (current) {
    if (entityByDeclaration.has(current) && isFunctionEntity(current)) {
      return entityByDeclaration.get(current);
    }
    current = current.parent;
  }
  return null;
}

function bodyForNode(node) {
  if (bodyByNode.has(node)) return bodyByNode.get(node);
  const position = sourcePosition(node);
  let kind = "expression";
  if (ts.isCallExpression(node)) kind = "call";
  else if (ts.isNewExpression(node)) kind = "construct";
  else if (ts.isStatement(node) || ts.isCaseClause(node) || ts.isDefaultClause(node)) kind = "statement";
  else if (ts.isIdentifier(node)) kind = "identifier";
  const id = stableId("body", ...nodeKey(node, ts.SyntaxKind[node.kind]));
  const operator = ts.isBinaryExpression(node) ? node.operatorToken.getText() :
    ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node) ? ts.tokenToString(node.operator) :
    ts.isConditionalExpression(node) ? "?:" : ts.isAwaitExpression(node) ? "await" : null;
  addNode("T3", id, kind, compact(node.getText(node.getSourceFile())), {
    ...position,
    syntax_kind: ts.SyntaxKind[node.kind],
    type: ts.isExpression(node) ? safeType(node) : null,
    operator,
    owner_function_id: ownerFunction(node),
    scope_id: nearestScope(node),
    type_facts: ts.isExpression(node) ? typeMetadata(node) : null,
    declared_type_facts: ts.isIdentifier(node) ? declaredTypeMetadata(node) : null,
  });
  bodyByNode.set(node, id);
  return id;
}

function proofForNode(node) {
  if (proofByNode.has(node)) return proofByNode.get(node);
  const position = sourcePosition(node);
  const id = stableId("source-proof", ...nodeKey(node, ts.SyntaxKind[node.kind]));
  addNode("T4", id, "source-span", `${position.file}:${position.start_line}`, {
    ...position,
    text: compact(node.getText(node.getSourceFile()), 800),
    syntax_kind: ts.SyntaxKind[node.kind],
  });
  proofByNode.set(node, id);
  return id;
}

function pathForNode(node, pathKind = "value") {
  let variants = pathByNode.get(node);
  if (!variants) {
    variants = new Map();
    pathByNode.set(node, variants);
  }
  if (variants.has(pathKind)) return variants.get(pathKind);
  const position = sourcePosition(node);
  const id = stableId("path", ...nodeKey(node, pathKind));
  addNode("T2", id, pathKind, compact(node.getText(node.getSourceFile())), {
    ...position,
    type: ts.isExpression(node) ? safeType(node) : null,
    owner_function_id: ownerFunction(node),
    roles: [],
    type_facts: ts.isExpression(node) ? typeMetadata(node) : null,
    declared_type_facts: ts.isIdentifier(node) ? declaredTypeMetadata(node) : null,
  });
  variants.set(pathKind, id);
  addEdge("EVIDENCED_BY", id, bodyForNode(node));
  return id;
}

function propertyPathForNode(node) {
  const pieces = [];
  let current = node;
  while (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) {
    if (ts.isPropertyAccessExpression(current)) {
      pieces.unshift(current.name.text);
      current = current.expression;
    } else {
      const argument = current.argumentExpression;
      const key = argument && ts.isStringLiteralLike(argument)
        ? argument.text : `[${compact(argument?.getText(current.getSourceFile()) || "?", 100)}]`;
      pieces.unshift(key);
      current = current.expression;
    }
  }
  if (!ts.isIdentifier(current) && current.kind !== ts.SyntaxKind.ThisKeyword) return null;
  let baseId = null;
  if (ts.isIdentifier(current)) {
    const declaration = lexicalDeclaration(current) || referencedDeclaration(current);
    baseId = declaration ? entityForDeclaration(declaration) : null;
  } else {
    baseId = ownerFunction(current);
  }
  if (!baseId || !pieces.length) return null;
  const pathText = pieces.map((piece) => piece.startsWith("[") ? piece : `.${piece}`).join("");
  const key = `${baseId}\u0000${pathText}`;
  if (propertyPathIds.has(key)) return propertyPathIds.get(key);
  const position = sourcePosition(node);
  const id = stableId("property-path", baseId, pathText);
  addNode("T2", id, "property-path", `${nodes.get(baseId)?.label || current.getText()}${pathText}`, {
    ...position,
    base_value_id: baseId,
    path: pathText.startsWith(".") ? pathText.slice(1) : pathText,
    dynamic: pieces.some((piece) => piece.startsWith("[")),
    owner_function_id: ownerFunction(node),
    type: safeType(node),
  });
  addEdge("HAS_PROPERTY_PATH", baseId, id);
  propertyPathIds.set(key, id);
  return id;
}

function targetForValueNode(node) {
  if (ts.isIdentifier(node)) {
    const declaration = lexicalDeclaration(node) || referencedDeclaration(node);
    return declaration ? entityForDeclaration(declaration) : null;
  }
  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    return propertyPathForNode(node);
  }
  return null;
}

function addDefinition(targetId, node, kind, origin, valueNode = null, declaration = null) {
  if (!targetId) return null;
  if (declaration && definitionByDeclaration.has(declaration)) {
    return definitionByDeclaration.get(declaration);
  }
  const history = definitionHistoryByTarget.get(targetId) || [];
  const position = sourcePosition(node);
  const id = stableId("definition", targetId, position.start_offset, history.length, kind);
  const valuePosition = valueNode ? sourcePosition(valueNode) : null;
  addNode("T2", id, "definition", nodes.get(targetId)?.label || node.getText(), {
    ...position,
    target_id: targetId,
    target_symbol_id: nodes.get(targetId)?.properties?.symbol_id || null,
    version: history.length,
    definition_kind: kind,
    origin,
    previous_definition_id: history.length ? history[history.length - 1] : null,
    value_start_offset: valuePosition?.start_offset ?? null,
    value_end_offset: valuePosition?.end_offset ?? null,
    operator: ts.isBinaryExpression(node) ? node.operatorToken.getText() : null,
    owner_function_id: ownerFunction(node),
    scope_id: nearestScope(node),
  });
  addEdge("DEFINES", targetId, id);
  if (history.length) addEdge("PREVIOUS_VERSION", history[history.length - 1], id);
  if (valueNode) addEdge("VALUE_FLOWS_TO", pathForNode(valueNode), id, { reason: kind });
  history.push(id);
  definitionHistoryByTarget.set(targetId, history);
  if (declaration) definitionByDeclaration.set(declaration, id);
  return id;
}

function currentDefinition(targetId, referenceNode) {
  const history = definitionHistoryByTarget.get(targetId) || [];
  if (!history.length) {
    const target = nodes.get(targetId);
    const baseId = target?.kind === "property-path"
      ? target.properties.base_value_id : null;
    const definitionId = addDefinition(
      targetId, referenceNode,
      baseId ? "property-read" : "implicit",
      baseId ? "property-read" : "unknown",
    );
    if (baseId) {
      const baseDefinition = currentDefinition(baseId, referenceNode);
      addEdge("PROPERTY_READ", baseDefinition, definitionId, { path: target.properties.path });
    }
    return definitionId;
  }
  const offset = sourcePosition(referenceNode).start_offset;
  for (let index = history.length - 1; index >= 0; index -= 1) {
    const definition = nodes.get(history[index]);
    if (!definition || definition.properties.start_offset > offset) continue;
    const valueStart = definition.properties.value_start_offset;
    const valueEnd = definition.properties.value_end_offset;
    if (valueStart !== null && valueStart <= offset && offset < valueEnd && index > 0) {
      return history[index - 1];
    }
    return history[index];
  }
  return history[0];
}

function isSimpleWriteTarget(node) {
  const parent = node.parent;
  return ts.isBinaryExpression(parent) && parent.left === node &&
    ASSIGNMENT_KINDS.has(parent.operatorToken.kind) &&
    parent.operatorToken.kind === ts.SyntaxKind.EqualsToken;
}

function isOutermostAccess(node) {
  const parent = node.parent;
  return !(
    (ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent)) &&
    parent.expression === node
  );
}

function addRuntimeRead(node, targetId) {
  if (!targetId || isSimpleWriteTarget(node)) return null;
  const position = sourcePosition(node);
  const id = stableId("read", ...nodeKey(node, targetId));
  const definitionId = currentDefinition(targetId, node);
  addNode("T2", id, "read", compact(node.getText(node.getSourceFile()), 180), {
    ...position,
    target_id: targetId,
    target_symbol_id: nodes.get(targetId)?.properties?.symbol_id || null,
    definition_id: definitionId,
    owner_function_id: ownerFunction(node),
    scope_id: nearestScope(node),
  });
  addEdge("READS_FROM", definitionId, id);
  addEdge("VALUE_FLOWS_TO", id, pathForNode(node), { reason: "read-value" });
  addEdge("READ_EVIDENCED_BY", id, bodyForNode(node));
  return id;
}

function addRole(nodeId, role, subtype, confidence = "high") {
  const node = nodes.get(nodeId);
  if (!node) return;
  const roles = node.properties.roles || [];
  if (!roles.some((item) => item.role === role && item.subtype === subtype)) {
    roles.push({ role, subtype, confidence });
  }
  node.properties.roles = roles;
}

function registerScope(
  node, scopeKind, parentScopeId = null, ownerFunctionId = null,
  positionOverride = null,
) {
  if (scopeByNode.has(node)) return scopeByNode.get(node);
  const position = positionOverride || (ts.isSourceFile(node) ? {
    file: relative(node.fileName), absolute_file: normalize(node.fileName),
    start_offset: 0, end_offset: node.getEnd(), start_line: 1,
    start_column: 1,
    end_line: node.getLineAndCharacterOfPosition(Math.max(0, node.getEnd() - 1)).line + 1,
    end_column: node.getLineAndCharacterOfPosition(Math.max(0, node.getEnd() - 1)).character + 1,
  } : sourcePosition(node));
  const id = stableId("scope", ...nodeKey(node, scopeKind));
  addNode("T2", id, "scope", scopeKind, {
    ...position,
    scope_kind: scopeKind,
    parent_scope_id: parentScopeId,
    owner_function_id: ownerFunctionId,
  });
  scopeByNode.set(node, id);
  scopeKinds.set(id, scopeKind);
  const sfId = ensureSourceFile(node.getSourceFile(), "scope-owner");
  addEdge("DECLARES_SCOPE", parentScopeId || sfId, id);
  return id;
}

function nearestScope(node) {
  let current = node;
  while (current) {
    if (scopeByNode.has(current)) return scopeByNode.get(current);
    current = current.parent;
  }
  return null;
}

function nearestHoistScope(scopeId) {
  let current = scopeId;
  while (current && !["function", "module"].includes(scopeKinds.get(current))) {
    current = nodes.get(current)?.properties?.parent_scope_id || null;
  }
  return current || scopeId;
}

function declarationSymbolKind(declaration) {
  let current = declaration;
  while (current && (
    ts.isBindingElement(current) || ts.isObjectBindingPattern(current) ||
    ts.isArrayBindingPattern(current)
  )) current = current.parent;
  if (ts.isParameter(current)) return "parameter";
  if (ts.isCatchClause(current?.parent) ||
      (ts.isVariableDeclaration(current) && ts.isCatchClause(current.parent))) {
    return "catch-parameter";
  }
  if (ts.isImportClause(declaration) || ts.isImportSpecifier(declaration) ||
      ts.isNamespaceImport(declaration)) return "import";
  const variable = ts.isVariableDeclaration(current) ? current :
    ts.isVariableDeclaration(declaration) ? declaration : null;
  if (variable && ts.isVariableDeclarationList(variable.parent)) {
    if (variable.parent.flags & ts.NodeFlags.Const) return "const";
    if (variable.parent.flags & ts.NodeFlags.Let) return "let";
    return "var";
  }
  if (ts.isPropertyDeclaration(declaration) || ts.isPropertySignature(declaration)) {
    return "property";
  }
  return ts.isBindingElement(declaration) ? "binding" : "variable";
}

function lexicalName(declaration) {
  const nameNode = declaration.name || declaration;
  return ts.isIdentifier(nameNode) || ts.isPrivateIdentifier(nameNode)
    ? nameNode.text : compact(nameNode.getText(declaration.getSourceFile()), 120);
}

function registerLexicalSymbol(
  nodeId, name, kind, scopeId, ownerFunctionId, declarationId = null,
  declaration = null,
) {
  if (!scopeId || !name || name.startsWith("<anonymous")) return;
  if (symbolIdsByTarget.has(nodeId)) return symbolIdsByTarget.get(nodeId);
  const target = nodes.get(nodeId);
  const symbolId = stableId("symbol", nodeId, scopeId, name, kind);
  const targetProperties = target?.properties || {};
  addNode("T2", symbolId, "symbol", name, {
    file: targetProperties.file,
    absolute_file: targetProperties.absolute_file,
    start_offset: targetProperties.start_offset,
    end_offset: targetProperties.end_offset,
    start_line: targetProperties.start_line,
    start_column: targetProperties.start_column,
    end_line: targetProperties.end_line,
    end_column: targetProperties.end_column,
    symbol_name: name, symbol_kind: kind, scope_id: scopeId,
    owner_function_id: ownerFunctionId, declaration_id: declarationId,
    target_id: nodeId, declared_type: targetProperties.type,
    parameter_position: targetProperties.parameter_position,
  });
  addEdge("DECLARES_SYMBOL", scopeId, symbolId);
  addEdge("SYMBOL_DECLARES", symbolId, nodeId);
  symbolIdsByTarget.set(nodeId, symbolId);
  const fact = { node_id: symbolId, target_id: nodeId, name, kind, scope_id: scopeId,
    owner_function_id: ownerFunctionId, declaration_id: declarationId,
    declaration };
  lexicalSymbols.push(fact);
  if (target) Object.assign(target.properties, {
    symbol_name: name, symbol_kind: kind, symbol_scope_id: scopeId,
    symbol_id: symbolId, owner_function_id: ownerFunctionId,
  });
  return symbolId;
}

// T0 source files and module dependencies.
for (const fileName of analysisFileNames) {
  const sf = program.getSourceFile(fileName);
  if (!sf) continue;
  ensureSourceFile(sf);
  moduleScopeIds.set(normalize(fileName), registerScope(sf, "module", null, null));
}

// AST leaf tokens replace the context-free scanner. A raw TypeScript scanner
// cannot know whether `/` begins a regular expression, and can consequently
// misread a backtick inside `/...` as a template start. The parsed syntax tree
// already contains the correct contextual token kinds. Comments are collected
// from compiler trivia ranges and merged into the same ordered stream.
for (const fileName of analysisFileNames) {
  const sf = program.getSourceFile(fileName);
  if (!sf) continue;
  const fileId = sourceFileIds.get(normalize(fileName));
  const lexical = new Map();
  const collectLeaves = (node) => {
    const children = node.getChildren(sf);
    if (!children.length) {
      if (node.kind !== ts.SyntaxKind.EndOfFileToken &&
          node.kind !== ts.SyntaxKind.SyntaxList) {
        const start = node.getStart(sf, false);
        const end = node.getEnd();
        if (end > start) lexical.set(`${start}:${end}:${node.kind}`, {
          start, end, tokenKind: node.kind, trivia: false,
        });
      }
      return;
    }
    for (const child of children) collectLeaves(child);
  };
  collectLeaves(sf);
  const commentKeys = new Set();
  const collectComments = (position) => {
    for (const range of ts.getLeadingCommentRanges(sf.text, position) || []) {
      const key = `${range.pos}:${range.end}:${range.kind}`;
      if (!commentKeys.has(key)) {
        commentKeys.add(key);
        lexical.set(key, {
          start: range.pos, end: range.end, tokenKind: range.kind, trivia: true,
        });
      }
    }
  };
  collectComments(0);
  const collectNodeComments = (node) => {
    collectComments(node.getFullStart());
    ts.forEachChild(node, collectNodeComments);
  };
  collectNodeComments(sf);
  const ordered = [...lexical.values()].sort((left, right) =>
    left.start - right.start || left.end - right.end || left.tokenKind - right.tokenKind);
  let previousTokenId = null;
  for (const token of ordered) {
    const { start, end, tokenKind } = token;
    const begin = sf.getLineAndCharacterOfPosition(start);
    const finish = sf.getLineAndCharacterOfPosition(Math.max(start, end - 1));
    const id = stableId("token", normalize(fileName), start, end, tokenKind);
    addNode("T4", id, "token", compact(sf.text.slice(start, end), 160), {
      file: relative(fileName),
      absolute_file: normalize(fileName),
      start_offset: start,
      end_offset: end,
      start_line: begin.line + 1,
      start_column: begin.character + 1,
      end_line: finish.line + 1,
      end_column: finish.character + 1,
      token_kind: ts.SyntaxKind[tokenKind],
      trivia: token.trivia,
    });
    addEdge("HAS_TOKEN", fileId, id);
    if (previousTokenId) addEdge("NEXT_TOKEN", previousTokenId, id);
    previousTokenId = id;
  }
}

function resolvedModule(sourceFile, specifier) {
  const resolution = ts.resolveModuleName(
    specifier,
    sourceFile.fileName,
    config.options,
    ts.sys,
  ).resolvedModule;
  return resolution?.resolvedFileName ? normalize(resolution.resolvedFileName) : null;
}

function importMetadata(statement) {
  const bindings = [];
  const clause = statement.importClause;
  if (!clause) return {
    symbols: "", form: "side-effect", import_kind: "value", bindings,
  };
  if (clause.name) bindings.push({ imported: "default", local: clause.name.text });
  if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
    bindings.push({ imported: "*", local: clause.namedBindings.name.text });
  } else if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
    for (const element of clause.namedBindings.elements) {
      bindings.push({
        imported: element.propertyName?.text || element.name.text,
        local: element.name.text,
        type_only: Boolean(element.isTypeOnly),
      });
    }
  }
  const form = clause.name && clause.namedBindings ? "default+named" :
    clause.name ? "default" :
    clause.namedBindings && ts.isNamespaceImport(clause.namedBindings) ? "namespace" : "named";
  return {
    symbols: clause.getText(statement.getSourceFile()), form,
    import_kind: clause.isTypeOnly ? "type" : "value", bindings,
  };
}

function exportMetadata(statement) {
  const names = [];
  if (statement.exportClause && ts.isNamedExports(statement.exportClause)) {
    for (const element of statement.exportClause.elements) {
      names.push(element.name.text);
    }
  }
  return {
    symbols: statement.exportClause?.getText(statement.getSourceFile()) || "*",
    names,
    form: statement.exportClause ? "named" : "star",
    export_kind: statement.isTypeOnly ? "type" : "value",
  };
}

for (const fileName of analysisFileNames) {
  const sf = program.getSourceFile(fileName);
  if (!sf) continue;
  const fileId = sourceFileIds.get(normalize(fileName));
  for (const statement of sf.statements) {
    if (!ts.isImportDeclaration(statement) && !ts.isExportDeclaration(statement)) continue;
    if (!statement.moduleSpecifier || !ts.isStringLiteralLike(statement.moduleSpecifier)) continue;
    const specifier = statement.moduleSpecifier.text;
    const resolved = resolvedModule(sf, specifier);
    let targetId = resolved && sourceFileIds.get(resolved);
    const resolvedSource = resolved ? program.getSourceFile(resolved) : null;
    if (!targetId && resolvedSource) {
      targetId = ensureSourceFile(resolvedSource, "imported-module");
    }
    if (!targetId) {
      targetId = stableId("external-module", specifier);
      const barePackage = specifier.startsWith("@")
        ? specifier.split("/").slice(0, 2).join("/") : specifier.split("/")[0];
      addNode("T0", targetId, "external-module", specifier, {
        specifier,
        resolved_file: resolved,
        package_name: specifier.startsWith(".") ? null : barePackage,
        provenance: specifier.startsWith(".") ? "unresolved-local" : "unresolved-dependency",
      });
    }
    const metadata = ts.isImportDeclaration(statement)
      ? importMetadata(statement) : exportMetadata(statement);
    const targetProperties = nodes.get(targetId)?.properties || {};
    addEdge(ts.isImportDeclaration(statement) ? "DEPENDS_ON" : "RE_EXPORTS", fileId, targetId, {
      specifier,
      type_only: ts.isImportDeclaration(statement) && Boolean(statement.importClause?.isTypeOnly),
      line: sourcePosition(statement).start_line,
      resolved_path: resolved,
      source_kind: targetProperties.provenance === "application" ||
        targetProperties.provenance === "workspace-library" ? "local" : "package",
      ...metadata,
    });
    const runtime = runtimeResolution(sf.fileName, specifier);
    const runtimeSource = runtime ? program.getSourceFile(runtime) : null;
    const runtimeTargetId = runtimeSource
      ? ensureSourceFile(runtimeSource, "runtime-import") : null;
    if (runtimeTargetId && runtimeTargetId !== targetId) {
      addEdge("RUNTIME_DEPENDS_ON", fileId, runtimeTargetId, {
        specifier,
        line: sourcePosition(statement).start_line,
        resolved_path: runtime,
        declaration_target_id: targetId,
      });
      addEdge("RUNTIME_IMPLEMENTATION", targetId, runtimeTargetId, {
        specifier,
        resolved_path: runtime,
      });
    }
  }
}

function controlScopeKind(node) {
  if (ts.isCatchClause(node)) return "catch";
  if (ts.isCaseBlock(node)) return "switch";
  if (ts.isForStatement(node) || ts.isForInStatement(node) || ts.isForOfStatement(node)) return "for";
  if (ts.isBlock(node)) {
    const parent = node.parent;
    if (ts.isForStatement(parent) || ts.isForInStatement(parent) ||
        ts.isForOfStatement(parent) || ts.isCatchClause(parent)) return null;
    if (ts.isIfStatement(parent)) return parent.elseStatement === node ? "else" : "if";
    if (ts.isWhileStatement(parent)) return "while";
    if (ts.isDoStatement(parent)) return "do";
    if (ts.isTryStatement(parent)) return node === parent.tryBlock ? "try" : "finally";
    if (ts.isCatchClause(parent)) return "catch-block";
    return "block";
  }
  return null;
}

// First pass: compiler declarations, lexical scopes and ownership.
for (const fileName of analysisFileNames) {
  const sf = program.getSourceFile(fileName);
  if (!sf) continue;
  const moduleScope = moduleScopeIds.get(normalize(fileName));
  const visit = (node, currentFunction = null, currentType = null, currentScope = moduleScope) => {
    let nextFunction = currentFunction;
    let nextType = currentType;
    let nextScope = currentScope;
    if (ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node) ||
        ts.isTypeAliasDeclaration(node) || ts.isEnumDeclaration(node) ||
        ts.isModuleDeclaration(node)) {
      nextType = registerEntity(node, currentType || currentFunction);
      nodes.get(nextType).properties.declaration_scope_id = currentScope;
      registerLexicalSymbol(
        nextType, declarationName(node), entityKind(node), currentScope,
        currentFunction, nextType, node,
      );
      if (ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node) ||
          ts.isEnumDeclaration(node) || ts.isModuleDeclaration(node)) {
        nextScope = registerScope(
          node, entityKind(node), currentScope, currentFunction,
        );
        nodes.get(nextType).properties.scope_id = nextScope;
        addEdge("HAS_SCOPE", nextType, nextScope);
      }
    }
    if (isFunctionEntity(node)) {
      nextFunction = registerEntity(node, currentType || currentFunction);
      functionStackByNode.set(node, nextFunction);
      const functionScope = registerScope(node, "function", currentScope, nextFunction);
      nextScope = functionScope;
      Object.assign(nodes.get(nextFunction).properties, {
        declaration_scope_id: currentScope,
        scope_id: functionScope,
      });
      addEdge("HAS_SCOPE", nextFunction, functionScope);
      registerLexicalSymbol(
        nextFunction, declarationName(node), entityKind(node), currentScope,
        currentFunction, nextFunction, node,
      );
      for (const parameter of node.parameters || []) valueForDeclaration(parameter, functionScope);
    } else {
      const scopeKind = controlScopeKind(node);
      if (scopeKind && !(ts.isBlock(node) && isFunctionEntity(node.parent))) {
        let scopePosition = null;
        if (ts.isCatchClause(node)) {
          scopePosition = sourcePosition(node.block);
        } else if (ts.isForStatement(node) || ts.isForInStatement(node) || ts.isForOfStatement(node)) {
          const firstScoped = node.initializer || node.expression || node.statement;
          scopePosition = {
            ...sourcePosition(node),
            start_offset: firstScoped.getStart(node.getSourceFile(), false),
            start_line: sourcePosition(firstScoped).start_line,
            start_column: sourcePosition(firstScoped).start_column,
          };
        }
        nextScope = registerScope(
          node, scopeKind, currentScope, currentFunction, scopePosition,
        );
      }
    }
    if (ts.isVariableDeclaration(node) || ts.isPropertyDeclaration(node) ||
        ts.isPropertySignature(node) || ts.isBindingElement(node) ||
        ts.isImportSpecifier(node) || ts.isNamespaceImport(node) ||
        (ts.isImportClause(node) && node.name)) {
      valueForDeclaration(node, nextScope);
    }
    ts.forEachChild(node, (child) => visit(child, nextFunction, nextType, nextScope));
  };
  visit(sf, null, null, moduleScope);
}

// Overload ownership and structural compatibility come from compiler symbols
// and types. They are direct type-system facts, not reconstructed declarations.
for (const [declaration, declarationId] of entityByDeclaration) {
  if (!isFunctionEntity(declaration) || declaration.body || !declaration.name) continue;
  try {
    const symbol = checker.getSymbolAtLocation(declaration.name);
    const implementation = (symbol?.declarations || []).find((candidate) =>
      isFunctionEntity(candidate) && Boolean(candidate.body));
    const implementationId = implementation ? entityForDeclaration(implementation) : null;
    if (implementationId && implementationId !== declarationId) {
      nodes.get(declarationId).properties.overload_of = implementationId;
      addEdge("OVERLOAD_OF", declarationId, implementationId, {
        compiler_resolved: true,
      });
    }
  } catch { /* an unresolved overload remains a body-less declaration */ }
}

const applicationTypeDeclarations = [...entityByDeclaration.entries()].filter(
  ([declaration, declarationId]) =>
    ["class", "interface", "type"].includes(nodes.get(declarationId)?.kind) &&
    rootSet.has(normalize(declaration.getSourceFile().fileName)),
);
for (const [sourceDeclaration, sourceId] of applicationTypeDeclarations) {
  let sourceType = null;
  try {
    sourceType = checker.getTypeAtLocation(sourceDeclaration.name || sourceDeclaration);
  } catch { /* malformed declarations remain represented without compatibility edges */ }
  if (!sourceType) continue;
  for (const [targetDeclaration, targetId] of applicationTypeDeclarations) {
    if (sourceId === targetId) continue;
    let targetType = null;
    try {
      targetType = checker.getTypeAtLocation(targetDeclaration.name || targetDeclaration);
    } catch { /* handled below */ }
    if (!targetType) continue;
    const requiredMembers = checker.getPropertiesOfType(targetType)
      .filter((member) => !(member.flags & ts.SymbolFlags.Optional))
      .map((member) => member.getName())
      .sort();
    if (!requiredMembers.length) continue;
    let compatible = false;
    try {
      compatible = Boolean(checker.isTypeAssignableTo?.(sourceType, targetType));
    } catch { /* compiler versions without the helper omit this exact fact */ }
    if (compatible) {
      addEdge("STRUCTURALLY_COMPATIBLE_WITH", sourceId, targetId, {
        matched_members: requiredMembers,
        compiler_resolved: true,
      });
    }
  }
}

// Compiler-owned inheritance and interface relationships seed dynamic dispatch
// without parsing class text or matching names globally.
for (const fileName of analysisFileNames) {
  const sf = program.getSourceFile(fileName);
  if (!sf) continue;
  const visitDispatchRelations = (node) => {
    if (ts.isClassDeclaration(node) && node.name) {
      for (const member of node.members) {
        if (!ts.isMethodDeclaration(member) || !member.name) continue;
        const memberId = entityByDeclaration.get(member);
        const name = ts.isIdentifier(member.name) || ts.isStringLiteralLike(member.name)
          ? member.name.text : null;
        if (!memberId || !name) continue;
        for (const clause of node.heritageClauses || []) {
          for (const heritageNode of clause.types) {
            try {
              const heritageType = checker.getTypeAtLocation(heritageNode);
              const inheritedSymbol = checker.getPropertyOfType(heritageType, name);
              for (const declaration of inheritedSymbol?.declarations || []) {
                const inheritedId = entityForDeclaration(declaration);
                if (!inheritedId || nodes.get(inheritedId)?.tier !== "T1") continue;
                addEdge(
                  clause.token === ts.SyntaxKind.ImplementsKeyword
                    ? "IMPLEMENTS_MEMBER" : "OVERRIDES",
                  memberId,
                  inheritedId,
                  { compiler_resolved: true },
                );
              }
            } catch { /* unresolved heritage remains in type extensions */ }
          }
        }
      }
    }
    ts.forEachChild(node, visitDispatchRelations);
  };
  visitDispatchRelations(sf);
}

// Same-scope duplicates and ancestor shadowing use compiler-owned scope IDs.
for (const symbol of lexicalSymbols) {
  if (symbol.kind !== "import" || !symbol.declaration) continue;
  const nameNode = symbol.declaration.name;
  if (!nameNode) continue;
  try {
    const alias = checker.getSymbolAtLocation(nameNode);
    const targetSymbol = alias && (alias.flags & ts.SymbolFlags.Alias)
      ? checker.getAliasedSymbol(alias) : null;
    const targetDeclaration = declarationForSymbol(targetSymbol);
    const targetId = entityForDeclaration(targetDeclaration);
    if (targetId) {
      nodes.get(symbol.node_id).properties.alias_target_id = targetId;
      addEdge("ALIASES", symbol.node_id, targetId, { compiler_resolved: true });
    }
  } catch { /* unresolved imports remain explicit module diagnostics */ }
}

const symbolsByScopeName = new Map();
for (const symbol of lexicalSymbols) {
  const key = `${symbol.scope_id}\u0000${symbol.name}`;
  if (symbolsByScopeName.has(key)) {
    const duplicate = symbolsByScopeName.get(key);
    nodes.get(symbol.node_id).properties.duplicate_of = duplicate.node_id;
    addEdge("DUPLICATES", symbol.node_id, duplicate.node_id);
  } else {
    symbolsByScopeName.set(key, symbol);
  }
}
for (const symbol of lexicalSymbols) {
  let parentScope = nodes.get(symbol.scope_id)?.properties?.parent_scope_id || null;
  while (parentScope) {
    const outer = symbolsByScopeName.get(`${parentScope}\u0000${symbol.name}`);
    if (outer) {
      nodes.get(symbol.node_id).properties.shadows = outer.node_id;
      addEdge("SHADOWS", symbol.node_id, outer.node_id);
      break;
    }
    parentScope = nodes.get(parentScope)?.properties?.parent_scope_id || null;
  }
}

// Export identities come from the checker, including re-exports and aliases.
for (const fileName of analysisFileNames) {
  const sf = program.getSourceFile(fileName);
  if (!sf) continue;
  const fileId = sourceFileIds.get(normalize(fileName));
  const moduleSymbol = checker.getSymbolAtLocation(sf);
  const names = [];
  if (moduleSymbol) {
    for (const exported of checker.getExportsOfModule(moduleSymbol)) {
      names.push(exported.getName());
      const declaration = declarationForSymbol(exported);
      const targetId = entityForDeclaration(declaration);
      if (targetId) addEdge("EXPORTS", fileId, targetId, { name: exported.getName() });
    }
  }
  moduleExportNames.set(normalize(fileName), new Set(names));
}

function callLabel(node) {
  return compact(node.expression.getText(node.getSourceFile()), 180);
}

function callMetadata(node) {
  const expression = node.expression;
  const callee = compact(expression.getText(node.getSourceFile()), 240);
  let receiverExpression = null;
  let receiverNode = null;
  let methodName = lastCallName(callee);
  let computedKeyExpression = null;
  if (ts.isPropertyAccessExpression(expression)) {
    receiverNode = expression.expression;
    receiverExpression = compact(expression.expression.getText(node.getSourceFile()), 240);
    methodName = expression.name.text;
  } else if (ts.isElementAccessExpression(expression)) {
    receiverNode = expression.expression;
    receiverExpression = compact(expression.expression.getText(node.getSourceFile()), 240);
    methodName = null;
    computedKeyExpression = expression.argumentExpression
      ? compact(expression.argumentExpression.getText(node.getSourceFile()), 240) : null;
    const key = literalValue(expression.argumentExpression);
    if (key.literal && typeof key.value === "string") methodName = key.value;
  }
  return {
    callee,
    form: ts.isNewExpression(node) ? "constructor" :
      receiverExpression ? "method" : "call",
    receiver_expression: receiverExpression,
    receiver_call_id: (
      (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) &&
      ts.isCallExpression(expression.expression)
    ) ? bodyForNode(expression.expression) : null,
    method_name: methodName,
    computed_key_expression: computedKeyExpression,
    receiver_type_facts: typeMetadata(receiverNode),
    frontend_extensions: {
      typescript: callTypeExtensions(node),
    },
  };
}

function lastCallName(label) {
  const normalized = label.split("?.").join(".");
  const separator = Math.max(normalized.lastIndexOf("."), normalized.lastIndexOf("["));
  const tail = normalized.slice(separator + 1);
  let result = "";
  for (const character of tail) {
    const code = character.codePointAt(0);
    const identifierCharacter = character === "_" || character === "$" ||
      (code >= 48 && code <= 57) || (code >= 65 && code <= 90) ||
      (code >= 97 && code <= 122);
    if (!identifierCharacter) break;
    result += character;
  }
  return result;
}

function callTypeExtensions(node) {
  try {
    const signature = checker.getResolvedSignature(node);
    const declaration = signature?.declaration;
    const predicate = signature ? checker.getTypePredicateOfSignature(signature) : null;
    return {
      selected_signature: signature
        ? checker.signatureToString(signature, node, ts.TypeFormatFlags.NoTruncation)
        : null,
      selected_declaration: declaration ? {
        file: normalize(declaration.getSourceFile().fileName),
        start_offset: declaration.getStart(declaration.getSourceFile(), false),
        end_offset: declaration.getEnd(),
      } : null,
      return_type: signature
        ? safeTypeFromType(checker.getReturnTypeOfSignature(signature), node) : "unknown",
      parameter_types: (signature?.parameters || []).map((parameter) =>
        safeTypeFromType(checker.getTypeOfSymbolAtLocation(parameter, node), node)),
      explicit_type_arguments: (node.typeArguments || []).map((argument) => safeType(argument)),
      signature_type_parameters: (signature?.typeParameters || []).map((parameter) =>
        safeTypeFromType(parameter, node)),
      type_predicate: predicate ? {
        kind: ts.TypePredicateKind[predicate.kind],
        parameter_name: predicate.parameterName || null,
        parameter_index: predicate.parameterIndex,
        type: predicate.type ? safeTypeFromType(predicate.type, node) : null,
      } : null,
    };
  } catch {
    return {
      selected_signature: null, selected_declaration: null, return_type: "unknown",
      parameter_types: [], explicit_type_arguments: [], signature_type_parameters: [],
      type_predicate: null,
    };
  }
}

function targetDeclarationsForCall(node) {
  const resolved = checker.getResolvedSignature(node)?.declaration || null;
  const candidates = [];
  try {
    const expressionType = checker.getTypeAtLocation(node.expression);
    const signatures = ts.isNewExpression(node)
      ? expressionType.getConstructSignatures()
      : expressionType.getCallSignatures();
    for (const candidate of signatures) {
      if (candidate.declaration) candidates.push(candidate.declaration);
    }
  } catch { /* unresolved dynamic call */ }
  const expression = node.expression;
  if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
    const receiver = expression.expression;
    const methodNames = [];
    if (ts.isPropertyAccessExpression(expression)) {
      methodNames.push(expression.name.text);
    } else {
      const key = literalValue(expression.argumentExpression);
      if (key.literal && typeof key.value === "string") methodNames.push(key.value);
      else if (expression.argumentExpression) {
        try {
          const keyType = checker.getTypeAtLocation(expression.argumentExpression);
          const alternatives = keyType.isUnion?.() ? keyType.types : [keyType];
          for (const alternative of alternatives) {
            if (alternative.isStringLiteral?.()) methodNames.push(alternative.value);
          }
        } catch { /* dynamic key stays unresolved */ }
      }
    }
    try {
      const receiverType = checker.getTypeAtLocation(receiver);
      const receiverTypes = receiverType.isUnion?.() ? receiverType.types : [receiverType];
      for (const receiverAlternative of receiverTypes) {
        for (const methodName of methodNames) {
          const member = checker.getPropertyOfType(receiverAlternative, methodName);
          for (const declaration of member?.declarations || []) candidates.push(declaration);
        }
      }
      if (["call", "apply", "bind"].includes(methodNames[0])) {
        for (const signature of receiverType.getCallSignatures()) {
          if (signature.declaration) candidates.push(signature.declaration);
        }
      }
    } catch { /* union/dynamic receiver remains an explicit unresolved call */ }
  }
  return { resolved, candidates: [...new Set(candidates)] };
}

function referencedDeclaration(identifier) {
  try {
    return declarationForSymbol(checker.getSymbolAtLocation(identifier));
  } catch {
    return null;
  }
}

function lexicalDeclaration(identifier) {
  try {
    const symbol = checker.getSymbolAtLocation(identifier);
    return symbol?.valueDeclaration || symbol?.declarations?.[0] || null;
  } catch {
    return null;
  }
}

function isRuntimeReference(identifier) {
  let current = identifier.parent;
  while (current && !ts.isSourceFile(current)) {
    if (ts.isTypeNode(current) || ts.isInterfaceDeclaration(current) ||
        ts.isTypeAliasDeclaration(current) || ts.isTypeParameterDeclaration(current) ||
        ts.isImportTypeNode(current)) return false;
    if (ts.isExpression(current) || ts.isStatement(current)) return true;
    current = current.parent;
  }
  return false;
}

function sequenceStatements(container) {
  const statements = container.statements ? [...container.statements] : [];
  for (let index = 0; index + 1 < statements.length; index += 1) {
    addEdge("EXECUTES_BEFORE", bodyForNode(statements[index]), bodyForNode(statements[index + 1]));
  }
}

function astChildMetadata(parent, child) {
  let role = "AST_CHILD";
  let position = null;
  if (ts.isBinaryExpression(parent)) {
    role = child === parent.left ? "LEFT_OPERAND" :
      child === parent.right ? "RIGHT_OPERAND" : role;
  } else if (ts.isConditionalExpression(parent)) {
    role = child === parent.condition ? "CONDITION" :
      child === parent.whenTrue ? "TRUE_VALUE" :
      child === parent.whenFalse ? "FALSE_VALUE" : role;
  } else if (ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent) ||
      ts.isAwaitExpression(parent) || ts.isYieldExpression(parent) ||
      ts.isAsExpression(parent) || ts.isTypeAssertionExpression(parent) ||
      ts.isNonNullExpression(parent) || ts.isSatisfiesExpression(parent) ||
      ts.isParenthesizedExpression(parent)) {
    role = "OPERAND";
  } else if (ts.isPropertyAccessExpression(parent)) {
    role = child === parent.expression ? "RECEIVER" :
      child === parent.name ? "PROPERTY" : role;
  } else if (ts.isElementAccessExpression(parent)) {
    role = child === parent.expression ? "RECEIVER" :
      child === parent.argumentExpression ? "PROPERTY_KEY" : role;
  } else if (ts.isCallExpression(parent) || ts.isNewExpression(parent)) {
    if (child === parent.expression) role = "CALLEE";
    else {
      position = parent.arguments ? [...parent.arguments].indexOf(child) : -1;
      if (position >= 0) role = "ARGUMENT";
      else position = null;
    }
  } else if (ts.isVariableDeclaration(parent)) {
    role = child === parent.initializer ? "ASSIGNED_VALUE" : role;
  } else if (ts.isReturnStatement(parent)) {
    role = child === parent.expression ? "RETURNED_VALUE" : role;
  } else if (ts.isThrowStatement(parent)) {
    role = child === parent.expression ? "THROWN_VALUE" : role;
  } else if (ts.isIfStatement(parent)) {
    role = child === parent.expression ? "CONDITION" :
      child === parent.thenStatement ? "TRUE_BRANCH" :
      child === parent.elseStatement ? "FALSE_BRANCH" : role;
  } else if (ts.isWhileStatement(parent) || ts.isDoStatement(parent)) {
    role = child === parent.expression ? "CONDITION" :
      child === parent.statement ? "LOOP_BODY" : role;
  } else if (ts.isForStatement(parent)) {
    role = child === parent.initializer ? "INITIALIZER" :
      child === parent.condition ? "CONDITION" :
      child === parent.incrementor ? "INCREMENT" :
      child === parent.statement ? "LOOP_BODY" : role;
  } else if (ts.isForInStatement(parent) || ts.isForOfStatement(parent)) {
    role = child === parent.initializer ? "ITERATOR" :
      child === parent.expression ? "ITERABLE" :
      child === parent.statement ? "LOOP_BODY" : role;
  } else if (ts.isExpressionStatement(parent)) {
    role = "EXPRESSION";
  } else if (ts.isCaseClause(parent)) {
    role = child === parent.expression ? "CASE_LABEL" : "CASE_BODY";
    if (role === "CASE_BODY") position = [...parent.statements].indexOf(child);
  } else if (ts.isDefaultClause(parent)) {
    role = "CASE_BODY";
    position = [...parent.statements].indexOf(child);
  }
  return position === null ? { role } : { role, position };
}

function callableTargetsForExpression(expression) {
  const targets = [];
  const addDeclaration = (declaration) => {
    if (!declaration) return;
    if (isFunctionEntity(declaration)) {
      targets.push(entityForDeclaration(declaration));
      return;
    }
    const initializer = declaration.initializer;
    if (initializer && isFunctionEntity(initializer)) {
      targets.push(entityForDeclaration(initializer));
    } else if (initializer && initializer !== expression) {
      targets.push(...callableTargetsForExpression(initializer));
    }
  };
  if (isFunctionEntity(expression)) {
    addDeclaration(expression);
  } else {
    try {
      let symbol = checker.getSymbolAtLocation(expression);
      if (symbol?.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
      for (const declaration of symbol?.declarations || []) addDeclaration(declaration);
    } catch { /* unresolved function values remain explicit values */ }
  }
  if (ts.isConditionalExpression(expression)) {
    targets.push(...callableTargetsForExpression(expression.whenTrue));
    targets.push(...callableTargetsForExpression(expression.whenFalse));
  }
  return [...new Set(targets.filter(Boolean))];
}

function addAllocation(node, owningFunction) {
  if (!ts.isNewExpression(node) && !ts.isObjectLiteralExpression(node) &&
      !ts.isArrayLiteralExpression(node) && !ts.isFunctionExpression(node) &&
      !ts.isArrowFunction(node)) return null;
  const position = sourcePosition(node);
  const id = stableId("allocation", ...nodeKey(node, ts.SyntaxKind[node.kind]));
  const allocationKind = ts.isNewExpression(node) ? "class-instance" :
    ts.isObjectLiteralExpression(node) ? "object" :
    ts.isArrayLiteralExpression(node) ? "array" : "function-object";
  addNode("T2", id, "allocation", compact(node.getText(node.getSourceFile()), 180), {
    ...position,
    allocation_kind: allocationKind,
    allocated_type: safeType(node),
    owner_function_id: owningFunction,
    module_singleton: !owningFunction,
  });
  addEdge("ALLOCATES", bodyForNode(node), id);
  addEdge("VALUE_FLOWS_TO", id, pathForNode(node), { reason: "allocation" });
  return id;
}

function addWrite(
  node, targetNode, valueNode, owningFunction, writeKind, explicitTargetId = null,
) {
  const targetId = explicitTargetId || targetForValueNode(targetNode);
  if (!targetId) return null;
  const position = sourcePosition(node);
  const id = stableId("write", ...nodeKey(node, `${targetId}:${writeKind}`));
  const target = nodes.get(targetId);
  addNode("T2", id, "write", compact(
    targetNode?.getText(node.getSourceFile()) || nodes.get(targetId)?.label || "write", 180,
  ), {
    ...position,
    write_kind: writeKind,
    target_id: targetId,
    value_id: valueNode ? pathForNode(valueNode) : null,
    property_path: target?.kind === "property-path" ? target.properties.path : null,
    owner_function_id: owningFunction,
    target_scope: target?.properties?.symbol_kind === "parameter" ? "parameter" :
      target?.properties?.symbol_kind === "import" ? "imported" :
      target?.properties?.owner_function_id ? "local" : "module",
  });
  addEdge("WRITES_TO", id, targetId);
  const evidenceNode = ts.isExpression(node) || ts.isStatement(node) ? node : valueNode;
  if (evidenceNode) addEdge("EVIDENCED_BY", id, bodyForNode(evidenceNode));
  else addEdge("EVIDENCED_BY", id, proofForNode(node));
  if (valueNode) addEdge("VALUE_FLOWS_TO", pathForNode(valueNode), id, { reason: writeKind });
  for (const functionId of valueNode ? callableTargetsForExpression(valueNode) : []) {
    addEdge("FUNCTION_VALUE", functionId, targetId, { write_id: id });
  }
  return id;
}

function addAggregatePropertyWrites(declaration, baseId, owningFunction) {
  const initializer = declaration.initializer;
  if (!initializer || !baseId) return;
  const entries = [];
  if (ts.isObjectLiteralExpression(initializer)) {
    for (const property of initializer.properties) {
      if (ts.isPropertyAssignment(property)) {
        const name = ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) ||
          ts.isNumericLiteral(property.name) ? property.name.text : null;
        if (name !== null) entries.push({ name, node: property, value: property.initializer });
      } else if (ts.isShorthandPropertyAssignment(property)) {
        entries.push({ name: property.name.text, node: property, value: property.name });
      } else if (ts.isMethodDeclaration(property)) {
        const name = ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)
          ? property.name.text : null;
        if (name !== null) entries.push({ name, node: property, value: property });
      }
    }
  } else if (ts.isArrayLiteralExpression(initializer)) {
    initializer.elements.forEach((value, index) => {
      if (!ts.isOmittedExpression(value)) entries.push({ name: String(index), node: value, value });
    });
  }
  for (const entry of entries) {
    const position = sourcePosition(entry.node);
    const propertyId = stableId("property-path", baseId, entry.name);
    addNode("T2", propertyId, "property-path", `${nodes.get(baseId)?.label}.${entry.name}`, {
      ...position,
      base_value_id: baseId,
      path: entry.name,
      dynamic: false,
      owner_function_id: owningFunction,
      type: safeType(entry.value),
    });
    addEdge("HAS_PROPERTY_PATH", baseId, propertyId);
    addWrite(
      entry.node, null, entry.value, owningFunction, "property-initializer", propertyId,
    );
  }
}

function addDynamicBehavior(node, behaviorKind, properties = {}) {
  const position = sourcePosition(node);
  const id = stableId("dynamic-behavior", ...nodeKey(node, behaviorKind));
  addNode("T3", id, "dynamic-behavior", behaviorKind, {
    ...position,
    behavior_kind: behaviorKind,
    expression: compact(node.getText(node.getSourceFile()), 300),
    owner_function_id: ownerFunction(node),
    ...properties,
  });
  addEdge("DYNAMIC_BEHAVIOR_AT", id, bodyForNode(node));
  addEdge("EVIDENCED_BY", id, proofForNode(node));
  return id;
}

function recordDirectDynamicBehavior(node) {
  if (ts.isCallExpression(node)) {
    if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      const argument = node.arguments[0];
      addDynamicBehavior(node, "dynamic-import", {
        literal_specifier: literalValue(argument).literal,
        specifier: literalValue(argument).value,
      });
    } else if (ts.isIdentifier(node.expression) && node.expression.text === "eval") {
      addDynamicBehavior(node, "eval", { static_resolution: "none" });
    } else if (ts.isIdentifier(node.expression) && node.expression.text === "require") {
      const argument = node.arguments[0];
      if (!literalValue(argument).literal) {
        addDynamicBehavior(node, "runtime-module-load", { static_resolution: "dynamic" });
      }
    } else if (ts.isPropertyAccessExpression(node.expression)) {
      const receiver = node.expression.expression.getText(node.getSourceFile());
      if (receiver === "Reflect") {
        addDynamicBehavior(node, "reflection", { operation: node.expression.name.text });
      } else if (receiver === "Object" &&
          ["defineProperty", "defineProperties", "setPrototypeOf"].includes(node.expression.name.text)) {
        addDynamicBehavior(node, "runtime-object-mutation", {
          operation: node.expression.name.text,
        });
      }
    }
  } else if (ts.isNewExpression(node)) {
    const name = node.expression.getText(node.getSourceFile());
    if (name === "Function") addDynamicBehavior(node, "new-function", { static_resolution: "none" });
    if (name === "Proxy") addDynamicBehavior(node, "proxy", { static_resolution: "runtime" });
  } else if (ts.isElementAccessExpression(node) &&
      !literalValue(node.argumentExpression).literal) {
    const parent = node.parent;
    const write = (ts.isBinaryExpression(parent) && parent.left === node &&
      ASSIGNMENT_KINDS.has(parent.operatorToken.kind)) ||
      ((ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent)) &&
       parent.operand === node);
    addDynamicBehavior(node, write ? "computed-property-write" : "computed-property-read", {
      key_expression: node.argumentExpression?.getText(node.getSourceFile()) || null,
    });
  } else if (ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      (ts.isPropertyAccessExpression(node.left) || ts.isElementAccessExpression(node.left))) {
    const left = node.left.getText(node.getSourceFile());
    if (left.includes(".prototype") || left === "module.exports" || left.startsWith("exports.")) {
      addDynamicBehavior(node, "monkey-patch", { target: left });
    }
  }
}

function recordStaticInitializer(node, owningFunction) {
  if (!ts.isClassStaticBlockDeclaration(node) &&
      !(ts.isPropertyDeclaration(node) && hasModifier(node, ts.SyntaxKind.StaticKeyword))) {
    return;
  }
  const position = sourcePosition(node);
  const ownerId = nodes.get(nearestScope(node))?.properties?.owner_function_id ||
    entityByDeclaration.get(node.parent) || null;
  const id = stableId("static-initializer", ...nodeKey(node, ownerId || "class"));
  addNode("T3", id, "static-initializer", compact(node.getText(node.getSourceFile()), 200), {
    ...position,
    owner_type_id: ownerId,
    owner_function_id: owningFunction,
    initializer_kind: ts.isClassStaticBlockDeclaration(node) ? "static-block" : "static-property",
  });
  addEdge("INITIALIZES_WITH", ownerId, id);
  addEdge("EVIDENCED_BY", id, proofForNode(node));
}

function recordModuleInitializers(sf, fileId) {
  let previous = null;
  let order = 0;
  for (const statement of sf.statements) {
    if (ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement) ||
        ts.isInterfaceDeclaration(statement) || ts.isTypeAliasDeclaration(statement) ||
        ts.isFunctionDeclaration(statement)) continue;
    const position = sourcePosition(statement);
    const id = stableId("module-initializer", ...nodeKey(statement, order));
    addNode("T3", id, "module-initializer", compact(statement.getText(sf), 220), {
      ...position,
      order,
      statement_kind: ts.SyntaxKind[statement.kind],
      side_effect_kind: ts.isVariableStatement(statement) ? "binding" :
        ts.isClassDeclaration(statement) ? "class-definition" :
        ts.isExpressionStatement(statement) ? "expression" : "module-load",
    });
    addEdge("INITIALIZES_WITH", fileId, id, { order });
    addEdge("EVIDENCED_BY", id, bodyForNode(statement));
    if (previous) addEdge("EXECUTES_BEFORE", previous, id);
    previous = id;
    order += 1;
  }
}

function unwrapRefinementExpression(node) {
  let current = node;
  while (current && (
    ts.isParenthesizedExpression(current) || ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) || ts.isNonNullExpression(current) ||
    ts.isSatisfiesExpression(current)
  )) current = current.expression;
  return current;
}

function refinementTarget(node) {
  let current = unwrapRefinementExpression(node);
  const properties = [];
  while (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) {
    if (ts.isPropertyAccessExpression(current)) {
      properties.unshift(current.name.text);
      current = unwrapRefinementExpression(current.expression);
    } else {
      const key = literalValue(current.argumentExpression);
      properties.unshift(key.literal ? String(key.value) :
        `[${compact(current.argumentExpression?.getText(current.getSourceFile()) || "?", 100)}]`);
      current = unwrapRefinementExpression(current.expression);
    }
  }
  if (!current || (!ts.isIdentifier(current) && current.kind !== ts.SyntaxKind.ThisKeyword)) {
    return null;
  }
  const targetId = current.kind === ts.SyntaxKind.ThisKeyword
    ? ownerFunction(current) : targetForValueNode(current);
  if (!targetId) return null;
  const symbolId = nodes.get(targetId)?.properties?.symbol_id ||
    symbolIdsByTarget.get(targetId) || targetId;
  return {
    expression: node,
    base_expression: current,
    target_id: targetId,
    symbol_id: symbolId,
    property_path: properties.join("."),
  };
}

function comparisonLiteral(node) {
  const current = unwrapRefinementExpression(node);
  const literal = literalValue(current);
  if (literal.literal) return {
    matched: true,
    value: literal.value,
    display: compact(current.getText(current.getSourceFile()), 160),
  };
  if (ts.isIdentifier(current) && current.text === "undefined") {
    return { matched: true, value: "undefined", display: "undefined" };
  }
  return { matched: false, value: null, display: null };
}

function addTypeRefinement(
  condition, targetExpression, refinementKind, narrowedType, trueBranch, details = {},
) {
  const target = refinementTarget(targetExpression);
  if (!target) return null;
  const position = sourcePosition(details.evidence_node || condition);
  const conditionId = bodyForNode(condition);
  const id = stableId(
    "type-refinement", ...nodeKey(
      details.evidence_node || condition,
      `${target.symbol_id}:${target.property_path}:${refinementKind}:${narrowedType}:${trueBranch}`,
    ),
  );
  addNode("T2", id, "type-refinement", narrowedType, {
    ...position,
    expression_id: conditionId,
    symbol_id: target.symbol_id,
    target_id: target.target_id,
    property_path: target.property_path,
    refinement_kind: refinementKind,
    narrowed_type: narrowedType,
    true_branch: trueBranch,
    false_excludes: narrowedType,
    owner_function_id: ownerFunction(condition),
    operator: details.operator || null,
    compared_value: details.compared_value,
    case_statement_id: details.case_statement_id || null,
  });
  addEdge("NARROWS_TYPE", conditionId, id, { true_branch: trueBranch });
  addEdge("REFINES_SYMBOL", id, target.symbol_id, {
    property_path: target.property_path,
  });
  return id;
}

const EQUALITY_OPERATORS = new Set([
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
]);

function recordConditionRefinements(condition, positive = true, rootCondition = condition) {
  const current = unwrapRefinementExpression(condition);
  if (!current) return;
  if (ts.isPrefixUnaryExpression(current) &&
      current.operator === ts.SyntaxKind.ExclamationToken) {
    recordConditionRefinements(current.operand, !positive, rootCondition);
    return;
  }
  if (ts.isBinaryExpression(current) && [
    ts.SyntaxKind.AmpersandAmpersandToken,
    ts.SyntaxKind.BarBarToken,
    ts.SyntaxKind.QuestionQuestionToken,
  ].includes(current.operatorToken.kind)) {
    recordConditionRefinements(current.left, positive, rootCondition);
    recordConditionRefinements(current.right, positive, rootCondition);
    return;
  }
  if (ts.isBinaryExpression(current) &&
      current.operatorToken.kind === ts.SyntaxKind.InstanceOfKeyword) {
    addTypeRefinement(
      rootCondition, current.left, "instanceof",
      compact(current.right.getText(current.getSourceFile()), 300), positive,
      { operator: "instanceof", evidence_node: current },
    );
    return;
  }
  if (ts.isBinaryExpression(current) && current.operatorToken.kind === ts.SyntaxKind.InKeyword) {
    const key = comparisonLiteral(current.left);
    if (key.matched) addTypeRefinement(
      rootCondition, current.right, "property-presence", `has:${key.display}`, positive,
      { operator: "in", compared_value: key.value, evidence_node: current },
    );
    return;
  }
  if (ts.isBinaryExpression(current) && EQUALITY_OPERATORS.has(current.operatorToken.kind)) {
    const equality = [
      ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.EqualsEqualsEqualsToken,
    ].includes(current.operatorToken.kind);
    const trueBranch = positive ? equality : !equality;
    const pairs = [[current.left, current.right], [current.right, current.left]];
    for (const [candidate, compared] of pairs) {
      const literal = comparisonLiteral(compared);
      if (!literal.matched) continue;
      const unwrapped = unwrapRefinementExpression(candidate);
      if (ts.isTypeOfExpression(unwrapped) && typeof literal.value === "string") {
        addTypeRefinement(
          rootCondition, unwrapped.expression, "typeof", String(literal.value), trueBranch,
          {
            operator: current.operatorToken.getText(), compared_value: literal.value,
            evidence_node: current,
          },
        );
        return;
      }
      const target = refinementTarget(unwrapped);
      if (!target) continue;
      const nullish = literal.value === null || literal.value === "undefined";
      const refinementKind = nullish && !equality ? "non-null" :
        target.property_path ? "discriminant" : "literal-equality";
      const narrowed = nullish && !equality ? "NonNullable" :
        target.property_path ? `${target.property_path}=${literal.display}` : literal.display;
      addTypeRefinement(
        rootCondition, unwrapped, refinementKind, narrowed, trueBranch,
        {
          operator: current.operatorToken.getText(), compared_value: literal.value,
          evidence_node: current,
        },
      );
      return;
    }
  }
  if (ts.isCallExpression(current)) {
    try {
      const signature = checker.getResolvedSignature(current);
      const predicate = signature ? checker.getTypePredicateOfSignature(signature) : null;
      if (predicate) {
        let targetExpression = null;
        if (predicate.parameterIndex >= 0) {
          targetExpression = current.arguments[predicate.parameterIndex];
        } else if (ts.isPropertyAccessExpression(current.expression) ||
            ts.isElementAccessExpression(current.expression)) {
          targetExpression = current.expression.expression;
        }
        if (targetExpression) addTypeRefinement(
          rootCondition, targetExpression, "type-predicate",
          predicate.type ? safeTypeFromType(predicate.type, current) : "truthy", positive,
          {
            operator: ts.TypePredicateKind[predicate.kind],
            evidence_node: current,
          },
        );
        return;
      }
    } catch { /* unresolved calls do not establish compiler-backed refinements */ }
  }
  if (refinementTarget(current)) {
    addTypeRefinement(rootCondition, current, "truthy", "truthy", positive, {
      evidence_node: current,
    });
  }
}

function recordSwitchRefinements(node) {
  const target = refinementTarget(node.expression);
  if (!target?.property_path) return;
  for (const clause of node.caseBlock.clauses) {
    if (!ts.isCaseClause(clause)) continue;
    const label = comparisonLiteral(clause.expression);
    if (!label.matched) continue;
    addTypeRefinement(
      node.expression, node.expression, "discriminated-union-case",
      `${target.property_path}=${label.display}`, true,
      {
        operator: "switch-case", compared_value: label.value,
        case_statement_id: bodyForNode(clause), evidence_node: clause.expression,
      },
    );
  }
}

function collectTypeBindings(formal, actual, location, bindings) {
  if (!formal || !actual) return;
  if (formal.flags & ts.TypeFlags.TypeParameter) {
    const name = formal.symbol?.getName?.() || safeTypeFromType(formal, location);
    bindings[name] = safeTypeFromType(actual, location);
    return;
  }
  const formalArguments = formal.aliasTypeArguments || formal.typeArguments || [];
  const actualArguments = actual.aliasTypeArguments || actual.typeArguments || [];
  for (let index = 0; index < Math.min(formalArguments.length, actualArguments.length); index += 1) {
    collectTypeBindings(formalArguments[index], actualArguments[index], location, bindings);
  }
}

function recordGenericSubstitution(node, callId, targetId, signature) {
  if (!signature) return null;
  const genericSignature = signature.target || signature;
  const typeParameters = [...(genericSignature.typeParameters || [])];
  if (!typeParameters.length) return null;
  const bindings = {};
  const explicit = [...(node.typeArguments || [])];
  for (let index = 0; index < Math.min(typeParameters.length, explicit.length); index += 1) {
    try {
      bindings[safeTypeFromType(typeParameters[index], node)] = safeType(explicit[index]);
    } catch { /* a malformed explicit type argument remains unbound */ }
  }
  const genericParameters = [...(genericSignature.parameters || [])];
  const instantiatedParameters = [...(signature.parameters || [])];
  const argumentsList = [...(node.arguments || [])];
  for (let index = 0; index < Math.min(genericParameters.length, argumentsList.length); index += 1) {
    try {
      const genericDeclaration = declarationForSymbol(genericParameters[index]);
      const instantiatedDeclaration = declarationForSymbol(instantiatedParameters[index]);
      const formal = checker.getTypeOfSymbolAtLocation(
        genericParameters[index], genericDeclaration || node,
      );
      const actual = instantiatedParameters[index]
        ? checker.getTypeOfSymbolAtLocation(
          instantiatedParameters[index], instantiatedDeclaration || node,
        ) : checker.getTypeAtLocation(argumentsList[index]);
      collectTypeBindings(formal, actual, node, bindings);
    } catch { /* partial inference is retained below */ }
  }
  const position = sourcePosition(node);
  const id = stableId("generic-substitution", ...nodeKey(node, targetId || "unresolved"));
  addNode("T2", id, "generic-substitution", "generic substitution", {
    ...position,
    call_id: callId,
    function_id: targetId,
    bindings,
    complete: typeParameters.every((parameter) =>
      Object.hasOwn(bindings, safeTypeFromType(parameter, node))),
    owner_function_id: ownerFunction(node),
  });
  addEdge("SUBSTITUTES_TYPE", callId, id, { function_id: targetId });
  return id;
}

// Second pass: AST/body, direct value flow, compiler-resolved calls and control.
for (const fileName of analysisFileNames) {
  const sf = program.getSourceFile(fileName);
  if (!sf) continue;
  const fileId = sourceFileIds.get(normalize(fileName));
  const exported = moduleExportNames.get(normalize(fileName)) || new Set();

  const visit = (node, parentBody = null, currentFunction = null) => {
    let owningFunction = currentFunction;
    if (isFunctionEntity(node)) owningFunction = entityByDeclaration.get(node) || currentFunction;

    const includeBody = node !== sf && (
      ts.isStatement(node) || ts.isExpression(node) ||
      ts.isCaseClause(node) || ts.isDefaultClause(node)
    );
    let bodyId = parentBody;
    if (includeBody) {
      bodyId = bodyForNode(node);
      addEdge("EVIDENCED_BY", bodyId, proofForNode(node));
      if (parentBody) addEdge("AST_CHILD", parentBody, bodyId, astChildMetadata(node.parent, node));
      else addEdge("CONTAINS_BODY", owningFunction || fileId, bodyId);
    }

    addAllocation(node, owningFunction);
    recordDirectDynamicBehavior(node);
    recordStaticInitializer(node, owningFunction);

    if (ts.isSourceFile(node) || ts.isBlock(node) || ts.isModuleBlock(node) || ts.isCaseBlock(node)) {
      sequenceStatements(node);
    }

    if (isFunctionEntity(node)) {
      addDefinition(entityByDeclaration.get(node), node, "initial", "function", null, node);
    } else if (ts.isParameter(node)) {
      const targetId = valueForDeclaration(node);
      addDefinition(
        targetId, node, "initial", "parameter", node.initializer || null, node,
      );
    } else if (ts.isVariableDeclaration(node) || ts.isBindingElement(node)) {
      const targetId = valueForDeclaration(node);
      let initializer = node.initializer || null;
      if (!initializer && ts.isBindingElement(node)) {
        let bindingOwner = node.parent;
        while (bindingOwner && !ts.isVariableDeclaration(bindingOwner) &&
            !ts.isParameter(bindingOwner) && !ts.isSourceFile(bindingOwner)) {
          bindingOwner = bindingOwner.parent;
        }
        initializer = bindingOwner?.initializer || null;
      }
      if (!initializer && ts.isVariableDeclaration(node) &&
          ts.isVariableDeclarationList(node.parent) &&
          (ts.isForOfStatement(node.parent.parent) || ts.isForInStatement(node.parent.parent))) {
        initializer = node.parent.parent.expression;
      }
      addDefinition(
        targetId, node, "declaration",
        initializer ? "expression" : "uninitialized", initializer, node,
      );
    } else if (ts.isImportSpecifier(node) || ts.isNamespaceImport(node) ||
        (ts.isImportClause(node) && node.name)) {
      const targetId = valueForDeclaration(node);
      addDefinition(targetId, node, "initial", "import", null, node);
    }

    if (ts.isParameter(node) && valueByDeclaration.has(node)) {
      const valueId = valueForDeclaration(node);
      const functionNode = node.parent;
      const functionName = declarationName(functionNode);
      if (exported.has(functionName) || hasModifier(functionNode, ts.SyntaxKind.ExportKeyword)) {
        addRole(valueId, "Source", "exported-parameter", "medium");
      }
    }

    if (ts.isVariableDeclaration(node) && node.initializer) {
      addEdge("VALUE_FLOWS_TO", pathForNode(node.initializer), valueForDeclaration(node), {
        reason: "initializer",
      });
      addWrite(node, node.name, node.initializer, owningFunction, "initializer");
      addAggregatePropertyWrites(node, valueForDeclaration(node), owningFunction);
    }

    if ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) &&
        isOutermostAccess(node)) {
      addRuntimeRead(node, propertyPathForNode(node));
    }

    if (ts.isIdentifier(node) && !ts.isDeclarationName(node)) {
      const declaration = referencedDeclaration(node);
      const target = declaration ? entityForDeclaration(declaration) : null;
      if (target) {
        const runtimeReference = isRuntimeReference(node);
        addEdge(runtimeReference ? "REFERS_TO" : "TYPE_REFERS_TO", bodyForNode(node), target);
        if (runtimeReference && nodes.get(target)?.tier === "T2") {
          addEdge("VALUE_FLOWS_TO", target, pathForNode(node), { reason: "read" });
        }
        const parent = node.parent;
        const partOfAccess =
          (ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent)) &&
          (parent.expression === node || parent.name === node || parent.argumentExpression === node);
        if (runtimeReference && !partOfAccess) {
          const lexical = lexicalDeclaration(node);
          addRuntimeRead(node, lexical ? entityForDeclaration(lexical) : target);
        }
      }
    }

    if (ts.isBinaryExpression(node) && ASSIGNMENT_KINDS.has(node.operatorToken.kind)) {
      addEdge("VALUE_FLOWS_TO", pathForNode(node.right), pathForNode(node.left), {
        reason: "assignment",
        operator: node.operatorToken.getText(),
      });
      if (ts.isIdentifier(node.left)) {
        const declaration = referencedDeclaration(node.left);
        const target = declaration ? valueForDeclaration(declaration) : null;
        if (target) addEdge("VALUE_FLOWS_TO", pathForNode(node.right), target, { reason: "write" });
      }
      const targetId = targetForValueNode(node.left);
      addWrite(node, node.left, node.right, owningFunction, "assignment");
      const definitionId = addDefinition(
        targetId, node, ts.isIdentifier(node.left) ? "assignment" : "property-write",
        "expression", node.right,
      );
      if (definitionId && node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
          (ts.isIdentifier(node.right) || ts.isPropertyAccessExpression(node.right) ||
           ts.isElementAccessExpression(node.right))) {
        const sourceId = targetForValueNode(node.right);
        if (sourceId) addEdge("ALIASES_VALUE", sourceId, targetId, {
          line: sourcePosition(node).start_line, definition_id: definitionId,
        });
      }
    } else if ((ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) &&
        [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(node.operator)) {
      const targetId = targetForValueNode(node.operand);
      addWrite(node, node.operand, node.operand, owningFunction, "update");
      addDefinition(targetId, node, "update", "expression", node.operand);
    }

    if (ts.isReturnStatement(node) && owningFunction) {
      const returnId = stableId("return-value", ...nodeKey(node, owningFunction));
      const position = node.expression ? sourcePosition(node.expression) : sourcePosition(node);
      addNode("T2", returnId, "return-value", compact(node.expression?.getText() || "", 240), {
        ...position,
        return_kind: "return", owner_function_id: owningFunction,
        origin: !node.expression ? "void" :
          ts.isLiteralExpression(node.expression) ? "literal" : "expression",
      });
      if (node.expression) {
        addEdge("VALUE_FLOWS_TO", pathForNode(node.expression), returnId, { reason: "return" });
      }
      addEdge("RETURNS_VALUE", returnId, owningFunction);
      addEdge("RETURN_EVIDENCED_BY", returnId, bodyForNode(node));
    } else if (ts.isThrowStatement(node) && node.expression && owningFunction) {
      const returnedPath = pathForNode(node.expression);
      const returnId = stableId("return-value", ...nodeKey(node, owningFunction));
      const position = sourcePosition(node.expression);
      addNode("T2", returnId, "return-value", compact(node.expression.getText(), 240), {
        ...position,
        return_kind: "throw", owner_function_id: owningFunction, origin: "expression",
      });
      addEdge("VALUE_FLOWS_TO", returnedPath, returnId, { reason: "throw" });
      addEdge("THROWS_VALUE", returnId, owningFunction);
      addEdge("RETURN_EVIDENCED_BY", returnId, bodyForNode(node));
    }

    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      const callId = bodyForNode(node);
      const label = callLabel(node);
      Object.assign(nodes.get(callId).properties, callMetadata(node));
      const pathId = pathForNode(node, "call-value");
      Object.assign(nodes.get(callId).properties, { value_id: pathId });
      Object.assign(nodes.get(pathId).properties, { callsite_id: callId });
      const { resolved, candidates } = targetDeclarationsForCall(node);
      const primaryTarget = resolved ? entityForDeclaration(resolved) : null;
      if (resolved && primaryTarget) {
        addEdge("INVOKES", callId, primaryTarget, {
          resolution: resolved.getSourceFile() && rootSet.has(normalize(resolved.getSourceFile().fileName))
            ? "compiler-local" : "compiler-external",
        });
        if (owningFunction && nodes.get(primaryTarget)?.tier === "T1") {
          addEdge("CALLS", owningFunction, primaryTarget, { callsite: callId });
        }
      }
      const candidateTargetIds = [];
      for (const declaration of candidates) {
      const targetId = entityForDeclaration(declaration);
      if (!targetId || nodes.get(targetId)?.tier !== "T1") continue;
        candidateTargetIds.push(targetId);
        if (targetId !== primaryTarget) {
          addEdge("MAY_INVOKE", callId, targetId, { reason: "overload-candidate" });
        }
      }
      if (!primaryTarget) {
        nodes.get(callId).properties.resolution = "dynamic-or-unresolved";
      } else {
        nodes.get(callId).properties.resolution = candidates.length > 1 ? "exact-overload" : "exact";
        nodes.get(callId).properties.primary_target_id = primaryTarget;
        nodes.get(callId).properties.candidate_target_ids = [...new Set(candidateTargetIds)];
      }
      const signature = checker.getResolvedSignature(node);
      recordGenericSubstitution(node, callId, primaryTarget, signature);
      const args = node.arguments ? [...node.arguments] : [];
      args.forEach((argument, index) => {
        const argId = pathForNode(argument, "argument");
        Object.assign(nodes.get(argId).properties, {
          callsite_id: callId, position: index,
        });
        addEdge("VALUE_FLOWS_TO", pathForNode(argument), argId, {
          reason: "argument-value",
          callsite: callId,
          position: index,
        });
        addEdge("HAS_ARGUMENT", pathId, argId, { position: index });
        const parameter = signature?.parameters?.[index] ||
          (signature?.parameters?.length && signature.parameters[signature.parameters.length - 1]);
        const declaration = declarationForSymbol(parameter);
        const parameterId = declaration ? valueForDeclaration(declaration) : null;
        if (parameterId) {
          addEdge("ARGUMENT_BINDS_PARAMETER", argId, parameterId, {
            position: index,
            callsite: callId,
          });
        }
        for (const functionId of callableTargetsForExpression(argument)) {
          addEdge("PASSES_CALLBACK", argId, functionId, {
            callsite: callId,
            position: index,
          });
        }
      });
      const shortName = lastCallName(label);
      if (SINK_NAMES.has(shortName)) addRole(pathId, "Sink", SINK_NAMES.get(shortName));
      if (shortName === "eval" || shortName === "Function" ||
          ts.isElementAccessExpression(node.expression) ||
          (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword)) {
        addRole(pathId, "Boundary", "dynamic-dispatch", "high");
      }
    }

    if (ts.isIfStatement(node)) {
      recordConditionRefinements(node.expression);
      addEdge("CONDITION", bodyForNode(node), bodyForNode(node.expression));
      addEdge("TRUE_BRANCH", bodyForNode(node.expression), bodyForNode(node.thenStatement));
      if (node.elseStatement) addEdge("FALSE_BRANCH", bodyForNode(node.expression), bodyForNode(node.elseStatement));
    } else if (ts.isConditionalExpression(node)) {
      recordConditionRefinements(node.condition);
      addEdge("TRUE_BRANCH", bodyForNode(node.condition), bodyForNode(node.whenTrue));
      addEdge("FALSE_BRANCH", bodyForNode(node.condition), bodyForNode(node.whenFalse));
    } else if (ts.isWhileStatement(node) || ts.isDoStatement(node) || ts.isForStatement(node)) {
      const condition = node.expression || node.condition;
      const statement = node.statement;
      if (condition && statement) {
        recordConditionRefinements(condition);
        addEdge("LOOP_TRUE", bodyForNode(condition), bodyForNode(statement));
        addEdge("LOOP_BACK", bodyForNode(statement), bodyForNode(condition));
      }
    } else if (ts.isForOfStatement(node) || ts.isForInStatement(node)) {
      addEdge("ITERATES", bodyForNode(node.expression), bodyForNode(node.statement));
      addEdge("LOOP_BACK", bodyForNode(node.statement), bodyForNode(node.expression));
    } else if (ts.isSwitchStatement(node)) {
      recordSwitchRefinements(node);
    } else if (ts.isTryStatement(node)) {
      addEdge("TRY_BODY", bodyForNode(node), bodyForNode(node.tryBlock));
      if (node.catchClause) addEdge("EXCEPTION_BRANCH", bodyForNode(node.tryBlock), bodyForNode(node.catchClause.block));
      if (node.finallyBlock) {
        addEdge("RUNS_FINALLY", bodyForNode(node.tryBlock), bodyForNode(node.finallyBlock));
        if (node.catchClause) addEdge("RUNS_FINALLY", bodyForNode(node.catchClause.block), bodyForNode(node.finallyBlock));
      }
    } else if (ts.isBinaryExpression(node) && [
      ts.SyntaxKind.AmpersandAmpersandToken,
      ts.SyntaxKind.BarBarToken,
      ts.SyntaxKind.QuestionQuestionToken,
    ].includes(node.operatorToken.kind)) {
      addEdge("SHORT_CIRCUIT_LEFT", bodyForNode(node), bodyForNode(node.left));
      addEdge("SHORT_CIRCUIT_RIGHT", bodyForNode(node.left), bodyForNode(node.right), {
        operator: node.operatorToken.getText(),
      });
    }

    ts.forEachChild(node, (child) => visit(child, bodyId, owningFunction));
  };
  visit(sf, null, null);
  recordModuleInitializers(sf, fileId);
}

// TypeScript resolves package calls through declarations, while runtime behavior
// lives in JavaScript implementation files. Keep both facts and bridge matching
// package entities so reachability can continue into dependency bodies.
const runtimeImplementations = new Map();
const implementationKey = (node) => {
  const owner = nodes.get(node.properties.owner_id);
  return [
    node.properties.package_name || "",
    node.kind,
    owner?.label || "",
    node.label,
  ].join("\u0000");
};
const packageEntities = [...nodes.values()].filter((node) =>
  node.tier === "T1" && node.properties.provenance === "dependency" &&
  node.properties.package_name,
);
for (const entity of packageEntities) {
  if (String(entity.properties.absolute_file || "").endsWith(".d.ts")) continue;
  const key = implementationKey(entity);
  const implementations = runtimeImplementations.get(key) || [];
  implementations.push(entity.id);
  runtimeImplementations.set(key, implementations);
}

const declarationImplementations = new Map();
for (const declaration of packageEntities) {
  if (!String(declaration.properties.absolute_file || "").endsWith(".d.ts")) continue;
  const implementations = runtimeImplementations.get(implementationKey(declaration)) || [];
  if (!implementations.length) continue;
  declarationImplementations.set(declaration.id, implementations);
  nodes.get(declaration.id).properties.runtime_implementation_ids = implementations;
  for (const implementationId of implementations) {
    addEdge("IMPLEMENTED_BY", declaration.id, implementationId, {
      reason: "package-declaration-runtime-source",
    });
  }
}

for (const edge of [...edges]) {
  if (edge.kind !== "INVOKES" && edge.kind !== "MAY_INVOKE") continue;
  const implementations = declarationImplementations.get(edge.target) || [];
  if (!implementations.length) continue;
  const call = nodes.get(edge.source);
  const runtimeTargets = new Set(call?.properties.runtime_target_ids || []);
  const candidates = new Set(call?.properties.candidate_target_ids || []);
  for (const implementationId of implementations) {
    runtimeTargets.add(implementationId);
    candidates.add(implementationId);
    addEdge("MAY_INVOKE", edge.source, implementationId, {
      reason: "dependency-runtime-implementation",
      declaration_target_id: edge.target,
    });
    if (call?.properties.owner_function_id) {
      addEdge("CALLS", call.properties.owner_function_id, implementationId, {
        callsite: edge.source,
        reason: "dependency-runtime-implementation",
      });
    }
  }
  if (call) Object.assign(call.properties, {
    runtime_target_ids: [...runtimeTargets],
    candidate_target_ids: [...candidates],
  });
}

const argumentBindingsByParameter = new Map();
for (const binding of edges) {
  if (binding.kind !== "ARGUMENT_BINDS_PARAMETER") continue;
  const bindings = argumentBindingsByParameter.get(binding.target) || [];
  bindings.push(binding);
  argumentBindingsByParameter.set(binding.target, bindings);
}
for (const [declarationId, implementationIds] of declarationImplementations) {
  const declarationParameters = [...nodes.values()].filter((node) =>
    node.kind === "parameter" && node.properties.owner_function_id === declarationId,
  );
  for (const implementationId of implementationIds) {
    const implementationParameters = [...nodes.values()].filter((node) =>
      node.kind === "parameter" && node.properties.owner_function_id === implementationId,
    );
    for (const declarationParameter of declarationParameters) {
      const implementationParameter = implementationParameters.find((node) =>
        node.properties.parameter_position === declarationParameter.properties.parameter_position,
      );
      if (!implementationParameter) continue;
      addEdge("IMPLEMENTED_BY", declarationParameter.id, implementationParameter.id, {
        reason: "package-parameter-position",
      });
      for (const binding of argumentBindingsByParameter.get(declarationParameter.id) || []) {
        addEdge("ARGUMENT_BINDS_PARAMETER", binding.source, implementationParameter.id, {
          ...binding.properties,
          declaration_parameter_id: declarationParameter.id,
          reason: "dependency-runtime-implementation",
        });
      }
    }
  }
}

// Compiler-resolved references identify closures without searching source text.
for (const edge of [...edges]) {
  if (edge.kind !== "REFERS_TO") continue;
  const reference = nodes.get(edge.source);
  const target = nodes.get(edge.target);
  const functionId = reference?.properties?.owner_function_id;
  const targetOwner = target?.properties?.owner_function_id;
  if (!functionId || targetOwner === functionId) continue;
  const functionNode = nodes.get(functionId);
  const owner = nodes.get(functionNode?.properties.owner_id);
  if (!functionNode || !owner || !["function", "method"].includes(owner.kind)) {
    continue;
  }
  const capturedSymbolId = target?.properties?.symbol_id;
  if (!capturedSymbolId) continue;
  const captures = functionNode.properties.capture_symbol_ids || [];
  if (!captures.includes(capturedSymbolId)) captures.push(capturedSymbolId);
  functionNode.properties.capture_symbol_ids = captures;
  addEdge("CAPTURES", functionId, capturedSymbolId, { reference_id: edge.source });
}

// Compiler diagnostics are proof-tier facts, not fatal extraction failures.
const diagnostics = [
  ...config.configErrors,
  ...program.getSyntacticDiagnostics(),
  ...program.getSemanticDiagnostics(),
].filter((diagnostic) => !diagnostic.file || compilerRootSet.has(normalize(diagnostic.file.fileName)));
for (const diagnostic of diagnostics) {
  const fileName = diagnostic.file?.fileName;
  const start = diagnostic.start || 0;
  const location = diagnostic.file
    ? diagnostic.file.getLineAndCharacterOfPosition(start)
    : { line: 0, character: 0 };
  const id = stableId("diagnostic", fileName || "config", start, diagnostic.code);
  addNode("T4", id, "diagnostic", `TS${diagnostic.code}`, {
    category: ts.DiagnosticCategory[diagnostic.category],
    message: ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"),
    file: fileName ? relative(fileName) : null,
    line: location.line + 1,
    column: location.character + 1,
  });
  if (fileName && sourceFileIds.has(normalize(fileName))) {
    addEdge("HAS_DIAGNOSTIC", sourceFileIds.get(normalize(fileName)), id);
  }
}

// Cross-tier structural relationships are explicit drill links. Other cross-tier
// edges remain semantic links and are retained under the source tier.
const tiers = Object.fromEntries(TIER_ORDER.map((tier) => [tier, {
  tier,
  name: TIER_NAMES[tier],
  nodes: [],
  edges: [],
  expands_to: [],
  links: [],
}]));

for (const node of nodes.values()) {
  const { tier, ...serialized } = node;
  tiers[tier].nodes.push(serialized);
}

const structural = new Set([
  "DECLARES", "DECLARES_MEMBER", "DECLARES_VALUE", "CONTAINS_BODY",
  "DECLARES_SCOPE", "DECLARES_SYMBOL", "SYMBOL_DECLARES", "HAS_SCOPE",
  "AST_CHILD", "EVIDENCED_BY", "HAS_ARGUMENT",
]);
for (const edge of edges) {
  const sourceTier = nodes.get(edge.source)?.tier;
  const targetTier = nodes.get(edge.target)?.tier;
  if (!sourceTier || !targetTier) continue;
  if (sourceTier === targetTier) tiers[sourceTier].edges.push(edge);
  else if (structural.has(edge.kind)) {
    tiers[sourceTier].expands_to.push({
      kind: "EXPANDS_TO",
      source: edge.source,
      target: edge.target,
      properties: {
        fact_origin: "compiler", confidence: "exact", evidence_ids: [],
        via: edge.kind,
      },
    });
  } else {
    tiers[sourceTier].links.push({ ...edge, properties: { ...edge.properties, target_tier: targetTier } });
  }
}

for (const tier of TIER_ORDER) {
  tiers[tier].nodes.sort((left, right) => left.id.localeCompare(right.id));
  for (const collection of ["edges", "expands_to", "links"]) {
    tiers[tier][collection].sort((left, right) =>
      `${left.kind}|${left.source}|${left.target}`.localeCompare(`${right.kind}|${right.source}|${right.target}`));
  }
}

const roleIndex = {};
for (const node of nodes.values()) {
  for (const role of node.properties.roles || []) {
    (roleIndex[role.role] ||= []).push(node.id);
  }
}
for (const ids of Object.values(roleIndex)) ids.sort();

const manifest = {
  version: 1,
  frontend_contract_version: CONTRACT_VERSION,
  frontend_id: FRONTEND_ID,
  generator: FRONTEND_ID,
  languages: ["typescript", "javascript"],
  capabilities: {
    lexical: "complete",
    syntax: "complete",
    modules: diagnostics.length ? "partial" : "complete",
    dependency_sources: diagnostics.length ? "partial" : "complete",
    scopes: "complete",
    symbols: "partial",
    types: diagnostics.length ? "partial" : "complete",
    calls: diagnostics.length ? "partial" : "complete",
    control_flow: "partial",
    direct_data_flow: "partial",
    heap_identity: "none",
    context_sensitivity: "none",
    branch_histories: "none",
    taint_policy: "none",
    runtime_models: "none",
    effects: "none",
    async_events: "none",
    dynamic_behavior: "partial",
    framework_wiring: "none",
    security_roles: "partial",
  },
  typescript_version: ts.version,
  typescript_loaded_from: loadedFrom,
  source_dir: sourceDir,
  tsconfig: config.configPath,
  root_file_count: applicationRootNames.length,
  analyzed_file_count: analysisFileNames.length,
  runtime_dependency_file_count: runtimeDependencyNames.length,
  dependency_file_limit: dependencyLimit,
  dependency_discovery_truncated: runtimeDependencyNames.length >= dependencyLimit,
  node_count: nodes.size,
  edge_count: edges.length,
  diagnostic_count: diagnostics.length,
  direct_flow_only: true,
  identity_scheme: "v2:<owner>:<namespace>:<kind>:<digest>",
  legacy_identity_property: "legacy_id",
  role_index: roleIndex,
  tiers: TIER_ORDER.map((tier) => ({
    tier,
    name: TIER_NAMES[tier],
    file: `${tier.toLowerCase()}_${TIER_NAMES[tier]}.json`,
    node_count: tiers[tier].nodes.length,
    edge_count: tiers[tier].edges.length,
    expands_to_count: tiers[tier].expands_to.length,
    cross_tier_link_count: tiers[tier].links.length,
  })),
};

fs.mkdirSync(outputDir, { recursive: true });
for (const tier of TIER_ORDER) {
  fs.writeFileSync(
    path.join(outputDir, `${tier.toLowerCase()}_${TIER_NAMES[tier]}.json`),
    `${JSON.stringify(tiers[tier], null, 2)}\n`,
  );
}
fs.writeFileSync(path.join(outputDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);

console.log(`TypeScript ${ts.version} loaded from ${loadedFrom}`);
console.log(
  `Analyzed ${applicationRootNames.length} application files and ` +
  `${analysisFileNames.length - applicationRootNames.length} reachable dependency files from ${sourceDir}`,
);
console.log(`Emitted ${nodes.size} nodes and ${edges.length} direct edges to ${outputDir}`);
for (const tier of manifest.tiers) {
  console.log(
    `${tier.tier} ${tier.name}: ${tier.node_count} nodes, ${tier.edge_count} edges, ` +
    `${tier.expands_to_count} drill links, ${tier.cross_tier_link_count} semantic links`,
  );
}
console.log(`Compiler diagnostics retained as proof: ${diagnostics.length}`);
