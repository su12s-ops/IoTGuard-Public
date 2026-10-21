"""Preserve operation outcomes across normalization, storage and evidence reads."""
FIELDS = ("operation", "result", "errno", "retval", "process_instance_id", "schema_version")


def semantics(payload):
    current = payload
    for _ in range(8):
        if not isinstance(current, dict):
            break
        if "result" in current and "operation" in current:
            return {key: current[key] for key in FIELDS if key in current}
        current = current.get("raw")
    return {}
