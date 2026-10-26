"""Validate repository-local Markdown links without fetching external URLs."""
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r'!?\[[^\]\n]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+"[^"]*")?\s*\)')


def main():
    paths = subprocess.check_output(
        ['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT,
    ).decode('utf-8').split('\0')
    existing = {name for name in paths if name and (ROOT / name).is_file()}
    errors = []
    count = 0
    for name in sorted(existing):
        if not name.endswith('.md'):
            continue
        count += 1
        if name.startswith('docs/') and Path(name).name != 'README.md' and not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*\.md', Path(name).name):
            errors.append(f'{name}: use lowercase kebab-case for documentation filenames')
        content = (ROOT / name).read_text(encoding='utf-8-sig')
        # Code examples are not navigable document links.
        content = re.sub(r'(?ms)^```.*?^```[^\n]*', '', content)
        for match in LINK.finditer(content):
            value = match.group(1).strip('<>')
            parsed = urlsplit(value)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            target = ((ROOT / name).parent / unquote(parsed.path)).resolve()
            try:
                relative = target.relative_to(ROOT).as_posix()
            except ValueError:
                errors.append(f'{name}: link escapes repository: {value}')
                continue
            if relative not in existing and not any(p.startswith(relative + '/') for p in existing):
                errors.append(f'{name}: missing published target: {value}')
    if errors:
        print('\n'.join(errors))
        raise SystemExit(1)
    print(f'Validated local links in {count} Markdown files; external URLs were not fetched.')


if __name__ == '__main__':
    main()
