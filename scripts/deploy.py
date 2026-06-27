import argparse
import json
import os
import sys

import requests

from rule_bundle import (
    build_bundle,
    detect_drift,
    export_rule_backup,
    fetch_kibana_rules,
    restore_rule_from_backup,
    scan_rule_sources,
)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

URL = os.getenv("KIBANA_URL")
USER = os.getenv("ELASTIC_USERNAME")
PASS = os.getenv("ELASTIC_PASSWORD")
SPACE_ID = os.getenv("KIBANA_SPACE", "default")

RULES_INPUT = "rules/"
NDJSON_OUTPUT = "rules/windows_rules.ndjson"
BUNDLE_BACKUP_DIR = "trash/bundles"


def _base_api():
    if not URL:
        raise ValueError("Missing KIBANA_URL")
    return URL.rstrip("/")


def _auth():
    return (USER, PASS)


def _import_api():
    return f"{_base_api()}{'' if SPACE_ID == 'default' else f'/s/{SPACE_ID}'}/api/detection_engine/rules/_import"


def _find_api():
    return f"{_base_api()}{'' if SPACE_ID == 'default' else f'/s/{SPACE_ID}'}/api/detection_engine/rules/_find"


def build_and_save_bundle():
    print("[*] Building merged NDJSON bundle...")
    source_rules, _, materialized_rules = build_bundle(RULES_INPUT, NDJSON_OUTPUT)
    print(f"[+] Bundle ready: {len(materialized_rules)} imported rules from {len(source_rules)} sources -> {NDJSON_OUTPUT}")
    return materialized_rules


def deploy():
    source_rules = build_and_save_bundle()
    print(f"[*] Deploying bundle to Space [{SPACE_ID}]...")
    with open(NDJSON_OUTPUT, "rb") as f:
        res = requests.post(
            _import_api(),
            headers={"kbn-xsrf": "true"},
            auth=_auth(),
            files={"file": ("rules.ndjson", f, "application/x-ndjson")},
            params={"overwrite": "true"},
            timeout=120,
            verify=False,
        )
    if res.status_code == 200:
        print(f"[+] Deployed successfully. Rules processed: {len(source_rules)}")
    else:
        print(f"[-] Deploy failed ({res.status_code}): {res.text}")


def synchronize():
    source_rules = build_and_save_bundle()
    kibana_rules = fetch_kibana_rules(_base_api(), _auth(), SPACE_ID)
    report = detect_drift(source_rules, kibana_rules)

    print(f"[*] Sync report for Space [{SPACE_ID}]")
    print(f"    Repo rules:   {report['summary']['repo']}")
    print(f"    Kibana rules: {report['summary']['kibana']}")
    print(f"    Only in repo:  {len(report['only_in_repo'])}")
    print(f"    Only in Kibana:{len(report['only_in_kibana'])}")
    print(f"    Changed:       {len(report['changed'])}")

    if report["only_in_repo"]:
        print("[*] Rules present in repo but missing in Kibana:")
        for rid in report["only_in_repo"]:
            print(f"    + {rid}")
    if report["only_in_kibana"]:
        print("[*] Rules present in Kibana but missing in repo:")
        for rid in report["only_in_kibana"]:
            print(f"    - {rid}")
    if report["changed"]:
        print("[*] Field-level drift:")
        for item in report["changed"]:
            print(f"    * {item['rule_id']} :: {item['name']}")
            for diff in item["diffs"]:
                print(f"        - {diff['field']}: repo={diff['local']!r} | kibana={diff['kibana']!r}")

    if not report["only_in_repo"] and not report["only_in_kibana"] and not report["changed"]:
        print("[+] Repo and Kibana are synchronized.")
    else:
        print("[!] Drift detected. Review the diff above before deploying.")
        print("[*] Synchronizing repo state to Kibana...")
        with open(NDJSON_OUTPUT, "rb") as f:
            res = requests.post(
                _import_api(),
                headers={"kbn-xsrf": "true"},
                auth=_auth(),
                files={"file": ("rules.ndjson", f, "application/x-ndjson")},
                params={"overwrite": "true"},
                timeout=120,
                verify=False,
            )
        if res.status_code != 200:
            print(f"[-] Sync failed ({res.status_code}): {res.text}")
            return
        print("[+] Sync import completed. Re-checking state...")
        refreshed = detect_drift(source_rules, fetch_kibana_rules(_base_api(), _auth(), SPACE_ID))
        if not refreshed["only_in_repo"] and not refreshed["only_in_kibana"] and not refreshed["changed"]:
            print("[+] Synchronization verified.")
        else:
            print("[!] Synchronization finished, but some drift still remains.")


def detect():
    source_rules = build_and_save_bundle()
    kibana_rules = fetch_kibana_rules(_base_api(), _auth(), SPACE_ID)
    report = detect_drift(source_rules, kibana_rules)
    print(json.dumps(report, ensure_ascii=False, indent=2))


def restore(rule_id=None, backup_file=None):
    if not backup_file and not rule_id:
        raise ValueError("restore requires either --rule-id or --backup-file")

    if backup_file:
        dest = restore_rule_from_backup(backup_file, RULES_INPUT)
        print(f"[+] Restored from backup: {dest}")
        return

    candidate = os.path.join(BUNDLE_BACKUP_DIR, rule_id, f"{rule_id}.json")
    if not os.path.exists(candidate):
        raise ValueError(f"Backup not found for rule: {rule_id}")

    dest = restore_rule_from_backup(candidate, RULES_INPUT)
    print(f"[+] Restored rule from bundle backup: {dest}")


def main():
    parser = argparse.ArgumentParser(description="SIEM rule bundle operations")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("deploy", help="Build bundle and import to Kibana")
    sub.add_parser("sync", help="Compare repo against Kibana with detailed drift")
    sub.add_parser("detect", help="Output machine-readable drift report")

    restore_parser = sub.add_parser("restore", help="Restore a single rule from backup or snapshot")
    restore_parser.add_argument("--rule-id", help="Rule ID to back up from repo")
    restore_parser.add_argument("--backup-file", help="Restore a specific backup JSON file")

    args = parser.parse_args()

    if args.command == "deploy":
        deploy()
    elif args.command == "sync":
        synchronize()
    elif args.command == "detect":
        detect()
    elif args.command == "restore":
        restore(args.rule_id, args.backup_file)


if __name__ == "__main__":
    main()
