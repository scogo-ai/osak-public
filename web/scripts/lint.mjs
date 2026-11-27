import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const required = [
  "static/index.html",
  "static/styles.css",
  "static/app.js",
  "static/favicon.svg",
  "static/privacy/index.html",
  "static/terms/index.html",
  "src/index.js",
  "wrangler.toml",
];

for (const file of required) {
  if (!existsSync(resolve(root, file))) throw new Error(`missing required web file: ${file}`);
}

for (const file of ["static/app.js", "src/index.js"]) {
  const result = spawnSync(process.execPath, ["--check", resolve(root, file)], { stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status || 1);
}

const client = readFileSync(resolve(root, "static/app.js"), "utf8");
if (/document\.cookie|navigator\.sendBeacon|google-analytics|plausible|segment/i.test(client)) {
  throw new Error("tracking or cookie API found in the public client");
}

console.log("Web lint passed");
