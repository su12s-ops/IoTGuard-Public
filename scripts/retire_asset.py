"""Retire one identity-checked SQLite asset and its dependent rows.

Dry-run by default. Apply first writes a scoped gzip archive, then deletes in
foreign-key order inside one transaction. Shared historical reports stay intact.
This script never starts application workers or opens a device connection.
"""
import argparse
import gzip
import json
import os
from pathlib import Path
import sqlite3


def ident(value):
    return '"' + value.replace('"', '""') + '"'


def plan(connection, asset_id, expected_host, expected_mac, provisional_ip=None, workers_stopped=False):
    connection.row_factory = sqlite3.Row
    asset = connection.execute('SELECT * FROM linux_asset WHERE id=?', (asset_id,)).fetchone()
    if asset is None:
        raise ValueError('Asset does not exist')
    if asset['ip_address'] != expected_host or (asset['mac_address'] or '').lower() != expected_mac.lower():
        raise ValueError('Asset identity mismatch; refusing retirement')
    if asset['distribution'] != 'openwrt':
        raise ValueError('This maintenance operation requires the expected OpenWrt asset')
    tables = {}
    for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
        name = row[0]
        columns = list(connection.execute('PRAGMA table_info(' + ident(name) + ')'))
        primary = [column['name'] for column in columns if column['pk']]
        if len(primary) == 1:
            tables[name] = {'pk': primary[0], 'columns': {column['name'] for column in columns},
                            'fks': list(connection.execute('PRAGMA foreign_key_list(' + ident(name) + ')'))}
    for name in tables:
        connection.execute('CREATE TEMP TABLE ' + ident('retire_' + name) + ' (key PRIMARY KEY)')

    def seed(name, where, parameters=()):
        if name not in tables:
            return
        connection.execute('INSERT OR IGNORE INTO ' + ident('retire_' + name) + ' SELECT ' + ident(tables[name]['pk'])
                           + ' FROM ' + ident(name) + ' WHERE ' + where, parameters)

    def selected(name):
        return [row[0] for row in connection.execute('SELECT key FROM ' + ident('retire_' + name))]

    def related(child, column, parent, parent_column):
        if child not in tables or parent not in tables or column not in tables[child]['columns']:
            return
        seed(child, ident(column) + ' IN (SELECT ' + ident(parent_column) + ' FROM ' + ident(parent)
             + ' WHERE ' + ident(parent_column) + " IS NOT NULL AND " + ident(parent_column) + " != '' AND "
             + ident(tables[parent]['pk']) + ' IN (SELECT key FROM ' + ident('retire_' + parent) + '))')

    labels = (asset['hostname'], expected_host)
    for name, info in tables.items():
        for column in ('asset_id', 'gateway_asset_id'):
            if column in info['columns']:
                seed(name, ident(column) + '=?', (asset_id,))
    seed('linux_asset', 'id=?', (asset_id,))
    for name, column in [('iot_device', 'ip'), ('scan_target', 'ip_address'), ('scan_run', 'target_ip'),
                         ('remediation_workflow_run', 'target_host'), ('device_observation', 'ip_address'),
                         ('demo_target', 'host')]:
        if name in tables and column in tables[name]['columns']:
            seed(name, ident(column) + '=?', (expected_host,))
    for name, column in [('runtime_event', 'hostname'), ('security_evidence', 'device_id'),
                         ('unified_analysis_run', 'target_ref'), ('agent_orchestration_run', 'target_ref'),
                         ('trace_run', 'target_ref'), ('lsm_policy', 'device_id')]:
        seed(name, ident(column) + ' IN (?,?)', labels)
    seed('trace_run', "target_ref=? AND target_type IN ('linux_asset','asset','device_connection')", (str(asset_id),))
    if provisional_ip:
        # Only a non-authoritative placeholder, never a MAC-identified device.
        for row in connection.execute('SELECT * FROM iot_device WHERE ip=?', (provisional_ip,)):
            metadata = json.loads(row['metadata_json'] or '{}')
            if (row['identity_source'] == 'banner_heuristic' and not row['vendor'] and not row['model']
                    and not metadata.get('mac_address') and not metadata.get('simulation')
                    and (row['identity_confidence'] or 0) <= .35):
                seed('iot_device', 'id=?', (row['id'],))

    for _ in range(len(tables) + 5):
        before = connection.total_changes
        for name, info in tables.items():
            for fk in info['fks']:
                if fk['table'] in tables:
                    related(name, fk['from'], fk['table'], fk['to'])
        related('unified_analysis_run', 'risk_id', 'risk_assessment', 'id')
        related('investigation_request', 'source_run_id', 'unified_analysis_run', 'run_id')
        related('investigation_request', 'reanalysis_run_id', 'unified_analysis_run', 'run_id')
        related('trace_event', 'trace_id', 'trace_run', 'trace_id')
        for name, info in tables.items():
            if name != 'trace_event' and 'trace_id' in info['columns']:
                related('trace_run', 'trace_id', name, 'trace_id')
        related('trace_run', 'harness_run_id', 'harness_run', 'id')
        for kind, parent, column in [('harness', 'harness_run', 'id'), ('unified_analysis', 'unified_analysis_run', 'run_id')]:
            seed('trace_run', 'run_ref_type=? AND run_ref_id IN (SELECT ' + ident(column) + ' FROM ' + ident(parent)
                 + ' WHERE ' + ident(tables[parent]['pk']) + ' IN (SELECT key FROM ' + ident('retire_' + parent) + '))', (kind,))
        risk_objects = {'risk-' + str(value) for value in selected('risk_assessment')}
        for row in connection.execute('SELECT id,selected_object_ids_json FROM analysis_report'):
            objects = set(json.loads(row['selected_object_ids_json'] or '[]'))
            if objects and objects.issubset(risk_objects):
                seed('analysis_report', 'id=?', (row['id'],))
        related('analysis_round', 'review_run_id', 'analysis_report', 'review_run_id')
        related('console_workflow', 'round_id', 'analysis_round', 'round_id')
        related('analysis_budget', 'workflow_id', 'console_workflow', 'id')
        if connection.total_changes == before:
            break
    else:
        raise ValueError('Dependency closure did not converge')
    for name in ('harness_run', 'unified_analysis_run', 'analysis_report', 'console_workflow'):
        active = connection.execute('SELECT COUNT(*) FROM ' + ident(name) + ' WHERE ' + ident(tables[name]['pk'])
            + ' IN (SELECT key FROM ' + ident('retire_' + name) + ") AND status IN ('running','queued_remote')").fetchone()[0]
        if active and not workers_stopped:
            raise ValueError('Target still has active work: ' + name)
    counts = {name: len(selected(name)) for name in tables if selected(name)}
    return tables, counts, dict(asset)


def apply(connection, tables, counts, archive):
    archive = Path(archive).resolve()
    archive.parent.mkdir(parents=True, exist_ok=True)
    connection.commit()  # Only temporary selection tables have been changed.
    connection.execute('BEGIN IMMEDIATE')
    baseline = {tuple(row) for row in connection.execute('PRAGMA foreign_key_check')}
    totals = {name: connection.execute('SELECT COUNT(*) FROM ' + ident(name)).fetchone()[0] for name in tables}
    try:
        with archive.open('xb') as raw:
            os.chmod(archive, 0o600)
            with gzip.GzipFile(fileobj=raw, mode='wb') as output:
                for name in counts:
                    query = 'SELECT * FROM ' + ident(name) + ' WHERE ' + ident(tables[name]['pk']) + ' IN (SELECT key FROM ' + ident('retire_' + name) + ')'
                    for row in connection.execute(query):
                        output.write((json.dumps({'table': name, 'row': dict(row)}, ensure_ascii=False) + '\n').encode())
        order, visiting, done = [], set(), set()
        def visit(parent):
            if parent in done or parent in visiting:
                return
            visiting.add(parent)
            for child, info in tables.items():
                if any(fk['table'] == parent for fk in info['fks']):
                    visit(child)
            visiting.remove(parent)
            done.add(parent)
            order.append(parent)
        for name in tables:
            visit(name)
        for name in order:
            if name in counts:
                connection.execute('DELETE FROM ' + ident(name) + ' WHERE ' + ident(tables[name]['pk'])
                                   + ' IN (SELECT key FROM ' + ident('retire_' + name) + ')')
        for name in tables:
            actual = connection.execute('SELECT COUNT(*) FROM ' + ident(name)).fetchone()[0]
            if actual != totals[name] - counts.get(name, 0):
                raise ValueError('Unexpected row changes: ' + name)
        if {tuple(row) for row in connection.execute('PRAGMA foreign_key_check')} - baseline:
            raise ValueError('Retirement introduced dangling foreign keys')
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return {'counts': counts, 'archive': str(archive), 'archive_bytes': archive.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True)
    parser.add_argument('--asset-id', type=int, required=True)
    parser.add_argument('--expected-ip', required=True)
    parser.add_argument('--expected-mac', required=True)
    parser.add_argument('--remove-provisional-ip')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--archive')
    parser.add_argument('--workers-stopped', action='store_true', help='Confirm all database writers and collectors are stopped')
    args = parser.parse_args()
    database = Path(args.database).resolve()
    if not database.is_file():
        raise SystemExit('Existing database required')
    connection = sqlite3.connect('file:' + database.as_posix() + '?mode=rw', uri=True, timeout=10)
    connection.execute('PRAGMA foreign_keys=ON')
    try:
        if args.apply and not args.workers_stopped:
            raise ValueError('Stop workers and confirm --workers-stopped before applying')
        tables, counts, asset = plan(connection, args.asset_id, args.expected_ip, args.expected_mac, args.remove_provisional_ip, args.workers_stopped)
        print(json.dumps({'asset': {key: asset[key] for key in ('id','hostname','ip_address','mac_address')},
                          'counts': counts, 'apply': args.apply}, ensure_ascii=True), flush=True)
        if args.apply:
            if not args.archive:
                raise ValueError('A scoped archive is required before deletion')
            print(json.dumps(apply(connection, tables, counts, args.archive)), flush=True)
    finally:
        connection.close()


if __name__ == '__main__':
    main()
