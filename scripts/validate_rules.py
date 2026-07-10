import json
from datetime import date, datetime
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"
SCHEMA_PATH = ROOT / "schemas" / "rule_metadata.schema.json"


def load_schema():
    with SCHEMA_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def iter_rule_files():
    for path in RULES_DIR.rglob("*"):
        if path.suffix.lower() in {".yml", ".yaml", ".json"} and path.is_file():
            yield path


def load_rule(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        if path.suffix.lower() in {".yml", ".yaml"}:
            return yaml.safe_load(handle) or {}
        return json.load(handle)


def extract_metadata(path: Path, payload):
    if path.suffix.lower() in {".yml", ".yaml"}:
        return payload.get("x_metadata")
    return payload.get("metadata")


def validate_rule_identity(path: Path, payload):
    if path.suffix.lower() in {".yml", ".yaml"}:
        return bool(payload.get("id") and payload.get("title"))
    return bool(payload.get("rule_id") and payload.get("name"))


def normalize_dates(value):
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, list):
        return [normalize_dates(item) for item in value]
    if isinstance(value, dict):
        return {key: normalize_dates(item) for key, item in value.items()}
    return value


def main():
    schema = load_schema()
    validator = Draft202012Validator(schema)
    errors = []
    checked = 0

    for path in iter_rule_files():
        payload = load_rule(path)
        checked += 1

        if not validate_rule_identity(path, payload):
            errors.append(f"{path}: missing primary identity fields")
            continue

        metadata = extract_metadata(path, payload)
        if not metadata:
            errors.append(f"{path}: missing metadata block")
            continue

        metadata = normalize_dates(metadata)

        for err in sorted(validator.iter_errors(metadata), key=lambda item: list(item.path)):
            field = ".".join(str(part) for part in err.path) or "<root>"
            errors.append(f"{path}: {field}: {err.message}")

    if errors:
        print("Rule metadata validation failed:")
        for err in errors:
            print(f" - {err}")
        raise SystemExit(1)

    print(f"Validated {checked} rule files successfully.")


if __name__ == "__main__":
    main()
