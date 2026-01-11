import json
from pathlib import Path

def save_snapshot(data, date):
    Path("data/snapshots").mkdir(parents=True, exist_ok=True)
    path = Path(f"data/snapshots/{date}.json")
    path.write_text(json.dumps(sorted(data), indent=2))

def load_snapshot(date):
    path = Path(f"data/snapshots/{date}.json")
    if path.exists():
        return json.loads(path.read_text())
    return []

def diff(old, new):
    return {
        "added": list(set(new) - set(old)),
        "removed": list(set(old) - set(new))
    }
