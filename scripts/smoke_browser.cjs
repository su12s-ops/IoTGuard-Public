// Run against a real built console: no API interception or synthetic responses.
// Usage: node scripts/smoke_browser.cjs [base-url] [output-directory]
const { chromium } = require('../frontend/node_modules/playwright');
const fs = require('node:fs');
const path = require('node:path');
const base = (process.argv[2] || 'http://127.0.0.1:18100').replace(/\/$/, '');
const output = process.argv[3] || 'reports/browser-smoke-' + Date.now();
(async () => {
  fs.mkdirSync(output, {recursive:true});
  const browser = await chromium.launch({channel:process.env.PLAYWRIGHT_CHANNEL || 'msedge',headless:true});
  const page = await browser.newPage({viewport:{width:1440,height:900}});
  const errors = [], requests = [], results = [];
  const pending = new Set(), navigationAborts = new WeakSet();
  page.on('request', r => pending.add(r));
  page.on('requestfinished', r => pending.delete(r));
  page.on('pageerror', e => errors.push(String(e)));
  page.on('requestfailed', r => {
    pending.delete(r);
    if (navigationAborts.has(r) && r.failure()?.errorText === 'net::ERR_ABORTED') return;
    errors.push(r.url()+': '+r.failure()?.errorText);
  });
  page.on('response', r => {if(r.url().includes('/api/')) requests.push({url:r.url(),status:r.status()});});
  try {
    for(const [route,title] of [['/','安全总览'],['/assets','资产与发现'],['/risks','漏洞与风险'],['/agents','智能研判中心'],['/repairs','修复与验证'],['/runtime','运行监控与审计']]) {
      for (const request of pending) navigationAborts.add(request);
      await page.goto(base+route);
      // The live console polls while a run is active. Network idleness is not
      // a readiness signal; wait for the rendered page and its data loaders.
      await page.locator('h1').waitFor({state:'visible'});
      await page.waitForFunction(() => !Array.from(document.querySelectorAll('.loading-line'))
        .some(element => element.getClientRects().length), null, {timeout:30000});
      // Await this finite wave, not every future polling request.
      let deadline;
      try {
        await Promise.race([
          Promise.all([...pending].map(async request => {
            const response = await request.response();
            if (response) await response.finished();
          })),
          new Promise((_, reject) => { deadline = setTimeout(() => reject(Error(route+': initial requests timed out')), 30000); })
        ]);
      } finally { clearTimeout(deadline); }
      const heading = await page.locator('h1').innerText();
      if(!heading.includes(title)) throw Error(route+': unexpected heading '+heading);
      const alerts = await page.locator('[role="alert"]').allTextContents();
      const notes = await page.locator('.error-banner[role="status"]').allTextContents();
      errors.push(...alerts);
      results.push({route,heading,alerts,configuration_notes:notes});
      console.log(JSON.stringify({route,heading,alerts}));
    }
    await page.screenshot({path:path.join(output,'runtime.png'),fullPage:true});
    const failed = requests.filter(r=>r.status>=400);
    const external = requests.filter(r=>new URL(r.url).origin!==new URL(base).origin);
    const result={at:new Date().toISOString(),base,passed:!errors.length&&!failed.length&&!external.length,results,errors,failed,external,api_requests:requests.length,scope:'real application HTTP; no model or device acceptance'};
    fs.writeFileSync(path.join(output,'browser-smoke.json'),JSON.stringify(result,null,2),{flag:'wx'});
    console.log(JSON.stringify(result,null,2));
    if(!result.passed) process.exitCode=1;
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
