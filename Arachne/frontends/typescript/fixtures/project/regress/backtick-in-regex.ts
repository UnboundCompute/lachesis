// Regression: a regular-expression literal that contains a backtick must stay a
// single RegularExpressionLiteral token. A tokenizer that mistakes the backtick
// for the start of a template literal swallows the rest of the file, and every
// function below vanishes. The line numbers here are the assertion — do not move.

const FENCE = /```/g;

function strip(value: string): string {
  let result = value;
  if (FENCE.test(result)) {
    result = result.replace(FENCE, "");
  }
  const trimmed = result.trim();
  if (trimmed.length === 0) {
    return "";
  }
  return trimmed;
}

function after(value: string): string {
  return strip(value).toUpperCase();
}
