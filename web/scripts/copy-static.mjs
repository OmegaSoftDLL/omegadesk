// Copies the static page assets next to the compiled scripts in dist/.
// `omegadesk-server --web-root web/dist` serves the whole directory.
import { cpSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");
mkdirSync(dist, { recursive: true });
for (const name of ["index.html", "style.css"]) {
  cpSync(join(root, "public", name), join(dist, name));
}
