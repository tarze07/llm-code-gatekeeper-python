// Fixture testowy reguł „nigdy" dla TypeScriptu/JavaScriptu (poza JSX-ową
// no-dangerous-html-unsanitized, która ma osobny fixture w never.tsx).
// Uruchomienie: semgrep --test --config rules/semgrep rules/semgrep/tests

import { exec, execFile, execSync } from "child_process";
import https from "https";

function runEval(input: string) {
  // ruleid: no-eval-on-input-js
  return eval(input);
}

function runFunctionCtor(input: string) {
  // ruleid: no-eval-on-input-js
  const f = new Function(input);
  return f();
}

function safeEval() {
  // ok: no-eval-on-input-js
  return eval("1 + 1");
}

function runShellTemplate(userInput: string) {
  // ruleid: no-shell-true-js
  exec(`ls ${userInput}`);
}

function runShellConcat(userInput: string) {
  // ruleid: no-shell-true-js
  execSync("rm -rf " + userInput);
}

function runShellSafe(userInput: string) {
  // ok: no-shell-true-js
  execFile("ls", [userInput]);
}

function tlsAgentDisabled() {
  // ruleid: no-tls-verify-disabled-js
  const agent = new https.Agent({ rejectUnauthorized: false });
  return agent;
}

function tlsEnvDisabled() {
  // ruleid: no-tls-verify-disabled-js
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

function tlsOk() {
  // ok: no-tls-verify-disabled-js
  const agent = new https.Agent({ rejectUnauthorized: true });
  return agent;
}
