"""Sequential real formal reviews; bounded waits, fixed authorized risks, no repairs."""
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
    req = urllib.request.Request(BASE+path, method=method, headers={'X-Control-Token': TOKEN}, data=b'null' if method=='POST' else None)
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)

def save(label, data):
    now = datetime.now(timezone.utc)
    filename = DIRECTORY / ('queued-review-'+now.strftime('%Y%m%dT%H%M%S%f')+'-'+label+'.json')
    with filename.open('x', encoding='utf-8') as output:
        json.dump({'at':now.isoformat(),'data':data}, output, ensure_ascii=False, indent=2)

def finish(batch, risk):
    for attempt in range(181):
        data = api('/api/analysis/runs/'+batch)
        if data.get('status') in TERMINAL:
            result = {'batch':data}
            if data.get('status') != 'no_candidates':
                result['unified'] = api('/api/unified/runs/UA-'+batch+'-'+str(risk))
            save(batch+'-terminal', result)
            print(json.dumps({'batch':batch,'risk':risk,'status':data.get('status'),'termination_reason':data.get('termination_reason')}, ensure_ascii=True), flush=True)
            return
        if attempt % 5 == 0:
            print(json.dumps({'batch':batch,'risk':risk,'status':data.get('status'),'wait_minutes':attempt/2}), flush=True)
        time.sleep(30)
    raise RuntimeError('Bounded wait expired; preserving running task, no reset or restart')

finish('3ae3502ffc55',129)
for asset, risk in [(4,130),(4,131),(4,132),(1,158)]:
    path = '/api/analysis/runs?asset_id='+str(asset)+'&risk_id='+str(risk)+'&batch_size=1'
    data = api(path, 'POST')
    save('risk-'+str(risk)+'-start',data)
    print(json.dumps({'asset':asset,'risk':risk,'start':data.get('run_id'),'status':data.get('status'),'selected':data.get('selected_object_ids')},ensure_ascii=True),flush=True)
    if data.get('selected_object_ids') != ['risk-'+str(risk)]:
        raise RuntimeError('Formal selection differs from fixed authorized risk; stopping')
    finish(data['run_id'],risk)
print('QUEUE_TERMINAL: all fixed scoped reviews reached terminal; this does not imply automatic success',flush=True)
