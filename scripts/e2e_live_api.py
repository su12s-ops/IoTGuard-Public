"""Authenticated live API actions with timestamped, non-overwriting evidence."""
import argparse
from datetime import datetime, timezone
import json
import sys
from pathlib import Path
import urllib.request
import urllib.error
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('method', choices=['GET', 'POST'])
    parser.add_argument('path')
    parser.add_argument('--body')
    parser.add_argument('--field', action='append', default=[], help='JSON key=value; value parsed as JSON when possible')
    args = parser.parse_args()
    if not args.path.startswith('/api/'):
        parser.error('API path required')
    if args.field:
        body = {}
        for item in args.field:
            key, value = item.split('=', 1)
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                pass
            body[key] = value
        args.body = json.dumps(body)
    if args.body is not None:
        json.loads(args.body)  # fail before network on malformed command-line JSON
    env = dotenv_values(ROOT / 'backend/.env.docker')
    request = urllib.request.Request('http://127.0.0.1:18000' + args.path,
        data=args.body.encode() if args.body is not None else (b'null' if args.method == 'POST' else None),
        headers={'X-Control-Token': env['LINUXGUARD_CONTROL_TOKEN'], 'Content-Type': 'application/json'},
        method=args.method)
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            status, result = response.status, json.load(response)
    except urllib.error.HTTPError as error:
        status = error.code
        result = json.loads(error.read())
    now = datetime.now(timezone.utc)
    directory = ROOT / (ROOT / 'reports/current-e2e-directory.txt').read_text(encoding='utf-8-sig').strip()
    record = {'at': now.isoformat(), 'method': args.method, 'path': args.path,
              'status': status, 'response': result}
    name = now.strftime('%Y%m%dT%H%M%S%fZ') + '-' + args.path.split('?')[0].strip('/').replace('/', '-') + '.json'
    with (directory / name).open('x', encoding='utf-8') as output:
        json.dump(record, output, ensure_ascii=False, indent=2)
    text = json.dumps(record, ensure_ascii=False, indent=2)
    print(text[:20000].encode(sys.stdout.encoding or 'utf-8', errors='backslashreplace').decode(sys.stdout.encoding or 'utf-8'))
    if len(text) > 20000:
        print('Full response saved to evidence file:', name)
    if status >= 400:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
