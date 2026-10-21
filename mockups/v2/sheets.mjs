import { chromium } from "../../frontend/node_modules/@playwright/test/index.mjs";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(here, "sheets");
fs.mkdirSync(out, { recursive: true });

const browser = await chromium.launch({ channel: "msedge", headless: true });
for (const theme of ["prism", "editorial", "nocturne"]) {
  const page = await browser.newPage({ viewport: { width: 2400, height: 1840 }, deviceScaleFactor: 1 });
  await page.goto("file:///" + path.join(here, "sheet.html").replaceAll("\\", "/") + `?theme=${theme}`, { waitUntil: "load" });
  await page.waitForFunction(() => [...document.images].every((img) => img.complete && img.naturalWidth > 0));
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(300);
  await page.screenshot({ path: path.join(out, `${theme}.png`) });
  await page.close();
  console.log("sheet", theme);
}
await browser.close();
