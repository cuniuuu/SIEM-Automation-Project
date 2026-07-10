import json
from pathlib import Path

import yaml


class MetadataLoader:
    def __init__(self, rules_dir="rules"):
        self.rules_dir = Path(rules_dir)
        self._cache = None

    def load(self, force_reload=False):
        if self._cache is not None and not force_reload:
            return self._cache

        mapping = {}
        for path in self.rules_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".yml", ".yaml", ".json"}:
                continue
            try:
                with path.open("r", encoding="utf-8") as handle:
                    payload = yaml.safe_load(handle) if path.suffix.lower() in {".yml", ".yaml"} else json.load(handle)
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            rule_id = payload.get("id") or payload.get("rule_id")
            if not rule_id:
                continue
            mapping[rule_id] = {
                "path": str(path),
                "title": payload.get("title") or payload.get("name") or rule_id,
                "metadata": payload.get("x_metadata") or payload.get("metadata") or {},
            }
        self._cache = mapping
        return mapping

    def get(self, rule_id):
        return self.load().get(rule_id)
