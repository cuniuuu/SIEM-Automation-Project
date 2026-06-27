import json
import os
import subprocess
import tempfile
import sys
import copy
import shutil

import requests
import yaml  # SỬA: Bảo đảm thư viện yaml được import đầy đủ ở đầu file

SUPPORTED_SOURCE_EXTENSIONS = (".yml", ".yaml", ".json")
DEFAULT_INTERVAL = "1m"
DEFAULT_FROM = "now-120s"


def get_sigma_path():
    sigma_path = shutil.which("sigma")
    if sigma_path:
        return sigma_path
    sigma_exe = os.path.join(os.path.dirname(sys.executable), "Scripts", "sigma.exe")
    return sigma_exe if os.path.exists(sigma_exe) else "sigma"


def _load_json_rule(path):
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    return payload[0] if isinstance(payload, list) and payload else payload


def load_rule_source(path):
    lower = path.lower()
    if lower.endswith((".yml", ".yaml")):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else None
    if lower.endswith(".json"):
        return _load_json_rule(path)
    return None


def extract_rule_identity(data):
    rule_id = str(data.get("rule_id") or data.get("id") or "").strip()
    name = str(data.get("name") or data.get("title") or data.get("description") or rule_id or "Unnamed Rule")
    enabled = bool(data.get("enabled", True))
    return rule_id, name, enabled


def scan_rule_sources(rules_dir):
    artifacts = []
    for root, _, files in os.walk(rules_dir):
        for file in files:
            if not file.lower().endswith(SUPPORTED_SOURCE_EXTENSIONS):
                continue
            path = os.path.join(root, file)
            data = load_rule_source(path)
            if not data:
                continue
            rule_id, name, enabled = extract_rule_identity(data)
            if not rule_id:
                continue
            artifacts.append(
                {
                    "source_path": path,
                    "kind": "json" if path.lower().endswith(".json") else "sigma",
                    "rule_id": rule_id,
                    "name": name,
                    "enabled": enabled,
                    "data": data,
                }
            )
    return artifacts


def _is_deprecated(data):
    return str(data.get("status", "")).lower() == "deprecated"


def normalize_for_import(rule, deprecated_ids):
    normalized = copy.deepcopy(rule)
    normalized.setdefault("interval", DEFAULT_INTERVAL)
    normalized.setdefault("from", DEFAULT_FROM)
    if "title" in normalized and "name" not in normalized:
        normalized["name"] = normalized["title"]
    normalized.setdefault("enabled", True)
    if _is_deprecated(normalized):
        normalized["enabled"] = False
    rid = str(normalized.get("id") or normalized.get("rule_id") or "").lower()
    if rid in deprecated_ids:
        normalized["enabled"] = False
    return normalized


def build_bundle(rules_dir, ndjson_output):
    deprecated_ids = set()
    source_rules = scan_rule_sources(rules_dir)
    for artifact in source_rules:
        if _is_deprecated(artifact["data"]):
            deprecated_ids.add(str(artifact["rule_id"]).lower())

    sigma_sources = [a for a in source_rules if a["kind"] == "sigma"]
    custom_sources = [a for a in source_rules if a["kind"] == "json"]

    materialized_rules = []
    with tempfile.TemporaryDirectory() as tmpdir:
        sigma_output = os.path.join(tmpdir, "sigma.ndjson")
        if sigma_sources:
            sigma_input = os.path.join(tmpdir, "sigma-input")
            os.makedirs(sigma_input, exist_ok=True)
            for artifact in sigma_sources:
                rel_name = os.path.basename(artifact["source_path"])
                shutil.copy2(artifact["source_path"], os.path.join(sigma_input, rel_name))
            cmd = [
                get_sigma_path(),
                "convert",
                "-t",
                "lucene",
                "-p",
                "ecs_windows",
                "-f",
                "siem_rule_ndjson",
                sigma_input,
                "--skip-unsupported",
                "-o",
                sigma_output,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, shell=False)
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or "Sigma conversion failed")
        lines = []
        if os.path.exists(sigma_output):
            with open(sigma_output, "r", encoding="utf-8") as f:
                for raw in f:
                    raw = raw.strip()
                    if not raw:
                        continue
                    rule = json.loads(raw)
                    normalized = normalize_for_import(rule, deprecated_ids)
                    lines.append(json.dumps(normalized, ensure_ascii=False))
                    materialized_rules.append(normalized)

        for artifact in custom_sources:
            normalized = normalize_for_import(artifact["data"], deprecated_ids)
            lines.append(json.dumps(normalized, ensure_ascii=False))
            materialized_rules.append(normalized)

        os.makedirs(os.path.dirname(ndjson_output), exist_ok=True)
        with open(ndjson_output, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    return source_rules, deprecated_ids, materialized_rules


def fetch_kibana_rules(base_url, auth, space_id):
    api = f"{base_url}{'' if space_id == 'default' else f'/s/{space_id}'}/api/detection_engine/rules/_find"
    page = 1
    per_page = 100
    rules = []
    while True:
        res = requests.get(
            api,
            auth=auth,
            headers={"kbn-xsrf": "true"},
            params={"page": page, "per_page": per_page},
            verify=False,
            timeout=30,
        )
        res.raise_for_status()
        payload = res.json()
        data = payload.get("data", [])
        if not data:
            break
        rules.extend(data)
        total = payload.get("total", 0)
        if page * per_page >= total:
            break
        page += 1
    return rules


def compare_rule_fields(local_rule, kibana_rule):
    interesting = [
        "enabled",
        "interval",
        "from",
        "description",
        "query",
        "risk_score",
        "severity",
        "language",
        "type",
    ]
    diffs = []
    for field in interesting:
        local_value = local_rule.get(field)
        remote_value = kibana_rule.get(field)
        if local_value != remote_value:
            diffs.append(
                {
                    "field": field,
                    "local": local_value,
                    "kibana": remote_value,
                }
            )

    local_threshold = local_rule.get("threshold")
    kibana_threshold = kibana_rule.get("threshold")
    if local_threshold != kibana_threshold:
        diffs.append(
            {
                "field": "threshold",
                "local": local_threshold,
                "kibana": kibana_threshold,
            }
        )
    return diffs


def normalize_kibana_rule(rule):
    normalized = copy.deepcopy(rule)
    if "name" in normalized and isinstance(normalized["name"], str) and normalized["name"].startswith("SIGMA - "):
        normalized["name"] = normalized["name"][8:]
    normalized.setdefault("enabled", True)
    return normalized


def detect_drift(local_rules, kibana_rules):
    local_map = {}
    for rule in local_rules:
        rid = str(rule.get("rule_id") or rule.get("id") or "").strip()
        if rid:
            local_map[rid] = rule
    kibana_map = {}
    for rule in kibana_rules:
        rid = str(rule.get("rule_id") or rule.get("id") or "").strip()
        if rid:
            kibana_map[rid] = rule

    local_ids = set(local_map)
    kibana_ids = set(kibana_map)
    report = {
        "only_in_repo": sorted(local_ids - kibana_ids),
        "only_in_kibana": sorted(kibana_ids - local_ids),
        "changed": [],
        "summary": {
            "repo": len(local_ids),
            "kibana": len(kibana_ids),
        },
    }

    for rid in sorted(local_ids & kibana_ids):
        local_rule = local_map[rid]
        kibana_rule = normalize_kibana_rule(kibana_map[rid])
        diffs = compare_rule_fields(local_rule, kibana_rule)
        if diffs:
            report["changed"].append(
                {
                    "rule_id": rid,
                    "name": local_rule.get("name") or local_rule.get("title") or rid,
                    "diffs": diffs,
                }
            )
    return report