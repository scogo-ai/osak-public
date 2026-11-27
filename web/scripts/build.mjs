import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const source = resolve(root, "static");
const destination = resolve(root, "dist");

if (!existsSync(source)) throw new Error("static/ is missing");
rmSync(destination, { recursive: true, force: true });
mkdirSync(destination, { recursive: true });
cpSync(source, destination, { recursive: true });

for (const required of ["index.html", "styles.css", "app.js", "favicon.svg", "privacy/index.html", "terms/index.html", "quickstart/index.html"]) {
  if (!existsSync(resolve(destination, required))) throw new Error(`build output is missing ${required}`);
}
console.log(`Built ${destination}`);
