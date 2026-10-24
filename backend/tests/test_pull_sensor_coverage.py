"""A completed pull window is reporting, never a continuous eBPF sensor."""
import json
from datetime import timedelta
from app import models
from app.services.runtime_telemetry import coverage


def test_recent_pull_window_is_reporting_and_preserves_unknown_loss(session_factory):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname='pull-window')
        db.add(asset); db.flush()
        sensor = models.RuntimeSensor(asset_id=asset.id, sensor_id='pull', source='logread',
            status='stopped', dropped_events=None, capabilities_json=json.dumps({'mode': 'pull'}))
        db.add(sensor); db.commit()
        result = coverage(db, asset.id)
        assert result['status'] == 'reporting'
        assert result['sensors'][0]['status'] == 'reporting'
        assert result['sensors'][0]['dropped_events'] is None
        assert sensor.status == 'stopped'  # read model does not rewrite lifecycle
        assert not result['absence_proves_safe']
        sensor.last_heartbeat_at = models.utcnow() - timedelta(seconds=121)
        db.commit()
        assert coverage(db, asset.id)['status'] == 'stale'


def test_failed_pull_is_not_promoted_to_reporting(session_factory):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname='failed-pull')
        db.add(asset); db.flush()
        db.add(models.RuntimeSensor(asset_id=asset.id, sensor_id='failed-pull', source='logread',
            status='failed', capabilities_json=json.dumps({'mode': 'pull'})))
        db.commit()
        result = coverage(db, asset.id)
        assert result['sensors'][0]['status'] == 'failed'
        assert result['status'] != 'reporting'


def test_mixed_reporting_and_stale_remains_degraded(session_factory):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname='mixed-pull')
        db.add(asset); db.flush()
        db.add_all([
            models.RuntimeSensor(asset_id=asset.id, sensor_id='pull', source='logread',
                status='stopped', capabilities_json=json.dumps({'mode': 'pull'})),
            models.RuntimeSensor(asset_id=asset.id, sensor_id='stale', source='falco',
                status='running', last_heartbeat_at=models.utcnow()-timedelta(minutes=5)),
        ])
        db.commit()
        assert coverage(db, asset.id)['status'] == 'degraded'
