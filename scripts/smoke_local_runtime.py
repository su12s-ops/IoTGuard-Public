"""Exercise a disposable local runtime over real HTTP, never a production DB.

Requires explicit --allow-reset: archives/resets derived data on this instance.
Only use with scripts/serve_local.py and its isolated data directory.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import httpx

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='http://127.0.0.1:18100')
    parser.add_argument('--token-file', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-reset', action='store_true')
    args = parser.parse_args()
    if not args.allow_reset:
        parser.error('Disposable instance only: explicit --allow-reset required')
    if httpx.URL(args.base).host not in {'127.0.0.1', 'localhost', '::1'}:
        parser.error('Only local loopback instances are permitted')
    token = args.token_file.read_text(encoding='utf-8').strip()
    checks = []
    with httpx.Client(base_url=args.base, trust_env=False, timeout=60) as client:
        def request(method, path, expected=200, authorized=False, **kwargs):
            response = client.request(method, path,
                headers={'X-Control-Token': token} if authorized else {}, **kwargs)
            assert response.status_code == expected, (method, path, response.status_code, response.text[:300])
            checks.append({'method': method, 'path': path, 'status': response.status_code})
            return response
        health = request('GET', '/api/health').json()
        assert health['status'] == 'ok' and health['database'] == 'ok'
        for route in ['/', '/assets', '/risks/1', '/agents', '/repairs', '/runtime']:
            assert 'text/html' in request('GET', route).headers['content-type']
        request('GET', '/api/not-found', 404)
        request('GET', '/static/not-found.js', 404)
        request('POST', '/api/rounds/start', 401, json={})
        request('POST', '/api/experiment/reset', 401, json={})
        with (ROOT / 'asset_inventory_sample.json').open('rb') as handle:
            imported = request('POST', '/api/assets/upload', authorized=True,
                files={'file': ('sample.json', handle, 'application/json')}).json()
        asset_id = imported['asset']['id']
        assert len(imported['asset']['packages']) == 3
        current = request('GET', '/api/rounds/current').json()
        assert any(d['asset_id'] == asset_id for d in current['devices'])
        started = request('POST', '/api/rounds/start', authorized=True,
                          json={'asset_id': asset_id}).json()
        # No intelligence/model result is invented for a sample-only instance.
        assert started['review'] is None or started['review'].get('model_called') is False
        archive = request('POST', '/api/experiment/archive', authorized=True,
                          json={'label': 'HTTP acceptance'}).json()
        snapshot = request('GET', '/api/experiment/archives/' + archive['filename'],
                           authorized=True).json()
        assert snapshot['summary']['assets'] >= 1
        reset = request('POST', '/api/experiment/reset', authorized=True,
                        json={'archive': True, 'label': 'HTTP reset acceptance'}).json()
        assert reset['archive'] and reset['kept']['assets'] >= 1
        assert len(request('GET', f'/api/assets/{asset_id}').json()['packages']) == 3
        request('GET', '/api/dashboard/summary')
        request('GET', '/api/experiment/state')
        request('GET', '/api/health')
    result = {'at': datetime.now(timezone.utc).isoformat(), 'base': args.base,
              'passed': True, 'checks': checks, 'check_count': len(checks),
              'scope': 'isolated real HTTP; sample inventory, no live model or device acceptance',
              'health_layers': health['layers']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    print(json.dumps({'passed': True, 'checks': len(checks), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
