"""Retry three reviews that previously made zero model calls due to an API outage.

Rewritten from the sequential runner: each object was returned to
reanalysis_required through the documented human-review interface, and the
original failed reports/traces are retained. No budget, prompt or gate change.
"""
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
BASE = 'http://127.0.0.1:18000'
DIRECTORY = ROOT / (ROOT / 'reports/current-e2e-directory.txt').read_text(encoding='utf-8-sig').strip()
TOKEN = dotenv_values(ROOT / 'backend/.env.docker')['LINUXGUARD_CONTROL_TOKEN']
TERMINAL = {'completed', 'failed', 'partial', 'human_review', 'interrupted', 'cancelled', 'no_candidates'}


def api(path, method='GET'):
    request = urllib.request.Request(BASE + path, method=method,
                                     headers={'X-Control-Token': TOKEN},
                                     data=b'null' if method == 'POST' else None)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def save(label, data):
    now = datetime.now(timezone.utc)
    name = DIRECTORY / ('retry-review-' + now.strftime('%Y%m%dT%H%M%S%f') + '-' + label + '.json')
    with name.open('x', encoding='utf-8') as output:
        json.dump({'at': now.isoformat(), 'data': data}, output, ensure_ascii=False, indent=2)


def wait(batch, risk):
    for attempt in range(181):
        data = api('/api/analysis/runs/' + batch)
        if data.get('status') in TERMINAL:
            result = {'batch': data}
            if data.get('status') != 'no_candidates':
                result['unified'] = api('/api/unified/runs/UA-' + batch + '-' + str(risk))
            save(batch + '-terminal', result)
            print(json.dumps({'batch': batch, 'risk': risk, 'status': data.get('status'),
                              'termination_reason': data.get('termination_reason')}), flush=True)
            return data.get('status')
        if attempt % 6 == 0:
            print(json.dumps({'batch': batch, 'risk': risk, 'status': data.get('status'),
                              'wait_minutes': round(attempt * 0.5, 1)}), flush=True)
        time.sleep(30)
    raise RuntimeError('bounded wait expired; running task left untouched')


results = {}
for asset, risk in [(4, 131), (4, 132), (1, 158)]:
    data = api('/api/analysis/runs?asset_id=%d&risk_id=%d&batch_size=1' % (asset, risk), 'POST')
    save('risk-%d-start' % risk, data)
    if data.get('selected_object_ids') != ['risk-%d' % risk]:
        raise RuntimeError('selection differs from the authorized retry object')
    results[risk] = wait(data['run_id'], risk)
print('RETRY_TERMINAL ' + json.dumps(results), flush=True)
