"""Bounded low-frequency monitoring of a real review; never starts model work."""
import json
from pathlib import Path
import sys
import time
import urllib.request
from datetime import datetime, timezone
ROOT = Path(__file__).resolve().parents[1]
run_id = sys.argv[1]
risk_id = int(sys.argv[2]) if len(sys.argv) > 2 else 128
directory = ROOT / (ROOT / 'reports/current-e2e-directory.txt').read_text(encoding='utf-8-sig').strip()
terminal = {'completed','failed','partial','human_review','interrupted','cancelled','no_candidates'}
for attempt in range(241):
    records = {}
    for path in ['/api/analysis/runs/'+run_id, '/api/unified/runs/UA-'+run_id+'-'+str(risk_id)]:
        with urllib.request.urlopen('http://127.0.0.1:18000'+path, timeout=20) as response:
            records[path] = json.load(response)
    now = datetime.now(timezone.utc)
    with (directory / ('review-watch-'+run_id+'-'+now.strftime('%Y%m%dT%H%M%S%f')+'.json')).open('x',encoding='utf-8') as output:
        json.dump({'at':now.isoformat(),'records':records},output,ensure_ascii=False,indent=2)
    batch = records['/api/analysis/runs/'+run_id]
    unified = list(records.values())[1]
    print(json.dumps({'at':now.isoformat(),'status':batch.get('status'),'stage':unified.get('stage_status'),'roles':{k:v.get('status') for k,v in unified.get('agents',{}).items()},'usage':unified.get('usage')},ensure_ascii=False),flush=True)
    if batch.get('status') in terminal:
        print('TERMINAL '+json.dumps(batch,ensure_ascii=False),flush=True)
        break
    time.sleep(15)
else:
    raise SystemExit('Monitoring time limit reached; task completion unknown')
