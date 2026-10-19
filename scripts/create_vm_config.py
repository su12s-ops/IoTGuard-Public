"""Generate a new VMware VMX from public profiles; never modify or boot a disk."""

import argparse
import json
import re
from pathlib import Path


def vmx_value(value: str) -> str:
    if any(char in value for char in ('"', '\r', '\n', '\x00', '|')):
        raise ValueError('VMX values cannot contain quotes, control characters or pipes')
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=['ubuntu', 'openwrt'], required=True)
    parser.add_argument('--disk', type=Path, required=True, help='Existing, powered-off VMDK descriptor')
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--vnet', default='VMnet2', help='Existing isolated VMware custom network')
    args = parser.parse_args()
    disk = args.disk.resolve(strict=True)
    if not disk.is_file() or disk.suffix.lower() != '.vmdk':
        parser.error('--disk must be an existing VMDK descriptor')
    if not re.fullmatch(r'VMnet(?:[0-9]|1[0-9])', args.vnet):
        parser.error('--vnet must be VMnet0 through VMnet19')
    root = Path(__file__).resolve().parents[1]
    profiles = json.loads((root / 'deploy/vm/profiles.json').read_text(encoding='utf-8'))
    settings = {'config.version': '8', '.encoding': 'UTF-8', **profiles[args.role]}
    custom_nic = 'ethernet1' if args.role == 'ubuntu' else 'ethernet0'
    settings[f'{custom_nic}.vnet'] = args.vnet
    settings['scsi0:0.fileName'] = str(disk)
    body = '\n'.join(f'{key} = "{vmx_value(value)}"' for key, value in settings.items()) + '\n'
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / f'iotguard-{args.role}.vmx'
    # Exclusive create: do not overwrite any existing VM identity/configuration.
    with output.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(body)
    print(f'Created {output.resolve()}; disk unchanged, VM not started.')


if __name__ == '__main__':
    main()
