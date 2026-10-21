import { chromium } from "../../frontend/node_modules/@playwright/test/index.mjs";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const shots = path.join(here, "shots");
fs.mkdirSync(shots, { recursive: true });

const themes = ["prism", "editorial", "nocturne"];
const pages = [
  ["overview.html", "overview"],
  ["assets.html", "assets"],
  ["risks.html", "risks"],
  ["risk-detail.html", "risk-detail"],
  ["agents.html", "agents"],
  ["repairs.html", "repairs"],
  ["runtime.html", "runtime"],
  ["reports.html", "reports"],
  ["soc.html", "soc"]
];

const browser = await chromium.launch({ channel: "msedge", headless: true });
const log = [];

for (const [file, name] of pages) {
  for (const theme of themes) {
    const page = await browser.newPage({
      viewport: { width: 1440, height: 960 },
      deviceScaleFactor: 2
    });
    await page.goto("file:///" + path.join(here, file).replaceAll("\\", "/"), { waitUntil: "load" });
    await page.evaluate((t) => { document.body.dataset.theme = t; }, theme);
    await page.evaluate(() => document.fonts.ready);
    await page.waitForTimeout(250);
    const size = await page.evaluate(() => ({
      sw: document.documentElement.scrollWidth,
      sh: document.documentElement.scrollHeight,
      h: document.querySelector(".page")?.getBoundingClientRect().height,
      content: document.querySelector(".content")?.getBoundingClientRect().height
    }));
    log.push(`${theme}-${name} scroll=${size.sw}x${size.sh} page=${Math.round(size.h || 0)} content=${Math.round(size.content || 0)}`);
    await page.screenshot({ path: path.join(shots, `${theme}-${name}.png`) });
    await page.close();
  }
}
await browser.close();
fs.writeFileSync(path.join(here, "render.log"), log.join("\n"), "utf8");
console.log(log.join("\n"));

