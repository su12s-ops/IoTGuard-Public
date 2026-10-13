// Build/browser verification with no dotenv input or production dist changes.
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { build, createServer } from "vite";
import configuration from "../vite.config.js";

const scriptPath = fileURLToPath(import.meta.url);
const root = dirname(dirname(scriptPath));
const mode = process.argv[2];
if (!["build", "e2e", "serve"].includes(mode)) throw new Error("Use build or e2e; serve is internal to Playwright");
const runtime = mode === "serve" ? process.argv[3] : await mkdtemp(join(tmpdir(), "iotguard-stage4-frontend-"));
if (!runtime) throw new Error("Missing isolated runtime");
process.env.VITE_API_BASE = "http://127.0.0.1:8000/api";
const options = { ...configuration, root, configFile: false, envDir: runtime,
  cacheDir: join(runtime, "vite-cache"), server: { host: "127.0.0.1", port: 4174, strictPort: true } };

if (mode === "serve") {
  const server = await createServer(options);
  await server.listen();
  for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, async () => { await server.close(); process.exit(0); });
} else if (mode === "build") {
  await build({ ...options, build: { ...configuration.build, outDir: join(runtime, "build"), emptyOutDir: false } });
  console.log(JSON.stringify({ mode, status: "PASS", runtime, productionDistModified: false }));
} else {
  const configPath = join(runtime, "playwright.config.mjs");
  const originalConfig = pathToFileURL(join(root, "playwright.config.js")).href;
  const command = `"${process.execPath}" "${scriptPath}" serve "${runtime}"`;
  await writeFile(configPath, `import original from ${JSON.stringify(originalConfig)};\nexport default { ...original, testDir: ${JSON.stringify(join(root, "tests", "e2e"))}, outputDir: ${JSON.stringify(join(runtime, "test-results"))}, webServer: { ...original.webServer, command: ${JSON.stringify(command)}, cwd: ${JSON.stringify(root)} } };\n`);
  const require = createRequire(join(root, "package.json"));
  const cli = join(dirname(require.resolve("@playwright/test/package.json")), "cli.js");
  const exitCode = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, "test", "--config", configPath], { cwd: root, stdio: "inherit", windowsHide: true });
    child.once("error", reject);
    child.once("exit", code => resolve(code ?? 1));
  });
  console.log(JSON.stringify({ mode, status: exitCode === 0 ? "PASS" : "FAIL", runtime, apiTraffic: "mocked_by_test_fixtures" }));
  process.exitCode = exitCode;
}
