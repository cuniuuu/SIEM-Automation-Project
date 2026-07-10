import logging
import os
import subprocess
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import urllib3
from dateutil import parser, tz
from dotenv import load_dotenv
from elasticsearch import Elasticsearch

from soar.action_executor import ActionExecutor
from soar.case_builder import CaseBuilder
from soar.case_store import CaseStore
from soar.metadata_loader import MetadataLoader
from soar.playbook_runner import PlaybookRunner

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("elasticsearch").setLevel(logging.ERROR)
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


class AlertMonitor:
    def __init__(self):
        self.branch = self._get_current_branch()
        print(f"[*] Detected Environment: {self.branch.upper()}")

        self.elastic_host = os.getenv("ELASTIC_HOST")
        self.auth = (os.getenv("ELASTIC_USER"), os.getenv("ELASTIC_PASS"))
        self.token = os.getenv("TELEGRAM_TOKEN")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID")
        self._validate_required_env()

        env_settings = {
            "main": {"index": os.getenv("INDEX_PROD"), "label": "PROD"},
            "dev": {"index": os.getenv("INDEX_DEV"), "label": "DEV"},
        }
        current_config = env_settings.get(self.branch, env_settings["dev"])

        self.index = current_config["index"]
        self.env_label = current_config["label"]
        self.es = Elasticsearch(self.elastic_host, basic_auth=self.auth, verify_certs=False)
        self.running = False
        self.last_checkpoint = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.last_sort_value = None
        self.sent_alerts_cache = deque(maxlen=500)

        self.metadata_loader = MetadataLoader()
        self.case_store = CaseStore(self.es, self.env_label)
        self.playbook_runner = PlaybookRunner(
            case_builder=CaseBuilder(),
            case_store=self.case_store,
            action_executor=ActionExecutor(self.send_telegram, self.case_store),
        )

    def _validate_required_env(self):
        required = {
            "ELASTIC_HOST": self.elastic_host,
            "ELASTIC_USER": self.auth[0],
            "ELASTIC_PASS": self.auth[1],
            "TELEGRAM_TOKEN": self.token,
            "TELEGRAM_CHAT_ID": self.chat_id,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(
                "Missing required environment variables in scripts/.env: "
                + ", ".join(missing)
            )

    def _get_current_branch(self):
        try:
            return subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"]).decode().strip()
        except Exception:
            return "dev"

    def send_telegram(self, message):
        try:
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            payload = {"chat_id": self.chat_id, "text": message, "parse_mode": "HTML"}
            requests.post(url, data=payload, timeout=10)
        except Exception as exc:
            print(f"\n[-] Telegram Error: {exc}")

    def _search_alerts(self):
        query = {
            "size": 1000,
            "query": {"bool": {"must": [{"range": {"@timestamp": {"gt": self.last_checkpoint}}}]}},
            "sort": [{"@timestamp": {"order": "asc"}}, {"_doc": {"order": "asc"}}],
        }
        if self.last_sort_value:
            query["search_after"] = self.last_sort_value
        return self.es.search(index=self.index, body=query)["hits"]["hits"]

    def _extract_context(self, source):
        rule_id = source.get("kibana.alert.rule.rule_id") or ""
        threshold_result = source.get("kibana.alert.threshold_result", {})
        terms = threshold_result.get("terms", [])
        threshold_count = threshold_result.get("count") or 0
        attacker_ip = terms[0].get("value") if terms else (source.get("source.ip") or "Unknown IP")

        user_name = source.get("user", {}).get("name") or source.get("winlog", {}).get("user", {}).get("name") or "Unknown"
        evidence = (
            source.get("powershell", {}).get("file", {}).get("script_block_text")
            or source.get("process", {}).get("command_line")
            or source.get("registry", {}).get("path")
            or source.get("source.ip")
            or source.get("host.name")
            or "N/A"
        )
        process_name = source.get("process", {}).get("name") or "N/A"

        if rule_id == "threshold-windows-invalid-user-brute-force":
            user_name = "Multiple Invalid Users"
            evidence = f"Attacker IP: {attacker_ip} (Threshold Count: {threshold_count})"
            process_name = "lsass.exe / Protocol: RDP-SMB"
        elif rule_id == "threshold-windows-brute-force":
            user_name = f"Aggregated Group ({attacker_ip})"
            evidence = f"Attacker IP: {attacker_ip} (Threshold Count: {threshold_count})"
            process_name = "lsass.exe / Protocol: RDP-SMB"

        return user_name, evidence, process_name

    def _aggregate_alerts(self, hits):
        aggregated = {}
        for hit in hits:
            alert_id = hit["_id"]
            if alert_id in self.sent_alerts_cache:
                continue

            source = hit["_source"]
            user_name, evidence, process_name = self._extract_context(source)
            fingerprint = f"{source.get('kibana.alert.rule.name')}|{user_name}|{evidence}"

            if fingerprint not in aggregated:
                aggregated[fingerprint] = {
                    "source": source,
                    "count": 1,
                    "last_time": source["@timestamp"],
                    "evidence": evidence,
                    "proc_name": process_name,
                    "user": user_name,
                    "rule": source.get("kibana.alert.rule.name") or "Security Alert",
                    "ids": [alert_id],
                }
            else:
                aggregated[fingerprint]["count"] += 1
                aggregated[fingerprint]["last_time"] = source["@timestamp"]
                aggregated[fingerprint]["ids"].append(alert_id)
        return aggregated

    def _format_telegram_message(self, alert, risk_score, local_time, parent_process):
        attempt_suffix = f" (x{alert['count']})" if alert["count"] > 1 else ""
        icon = "🔴" if risk_score >= 70 else "🟡" if risk_score >= 40 else "🔵"
        return (
            f"{icon} <b>{self.env_label} RISK ALERT{attempt_suffix}</b>\n"
            f"Risk Score: <code>{risk_score}</code>\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"- Time: <code>{local_time}</code> | User/Target: <code>{alert['user']}</code>\n"
            f"- Rule: <i>{alert['rule']}</i>\n"
            f"─────────────────────\n"
            f"- Parent: <code>{parent_process.upper()}</code>\n"
            f"- Process: <code>{alert['proc_name'].upper()}</code>\n"
            f"- Evidence:\n<code>{str(alert['evidence']).strip()[:500]}</code>\n"
            f"━━━━━━━━━━━━━━━━━━━━━"
        )

    def _advance_checkpoint(self, hits):
        last_hit_dt = parser.isoparse(hits[-1]["_source"]["@timestamp"])
        safety_checkpoint = last_hit_dt - timedelta(seconds=15)
        self.last_checkpoint = safety_checkpoint.isoformat().replace("+00:00", "Z")
        self.last_sort_value = hits[-1]["sort"]

    def run_logic(self, log_callback):
        log_callback(f"[*] SOC MONITORING ACTIVE: {self.env_label}")
        while self.running:
            try:
                hits = self._search_alerts()
                if not hits:
                    time.sleep(5)
                    continue

                aggregated_alerts = self._aggregate_alerts(hits)
                for alert in aggregated_alerts.values():
                    source = alert["source"]
                    risk_score = source.get("kibana.alert.rule.risk_score") or 0
                    parent_process = source.get("process", {}).get("parent", {}).get("name") or (
                        "NT AUTHORITY\\SYSTEM" if source.get("kibana.alert.rule.type") == "threshold" else "N/A"
                    )
                    local_time = parser.isoparse(alert["last_time"]).astimezone(tz.tzlocal()).strftime("%H:%M:%S")
                    message = self._format_telegram_message(alert, risk_score, local_time, parent_process)
                    metadata_record = self.metadata_loader.get(source.get("kibana.alert.rule.rule_id"))

                    try:
                        self.playbook_runner.run(source, alert, metadata_record, self.env_label, message, log_callback)
                    except Exception as exc:
                        log_callback(f"[-] SOAR playbook error: {exc}")
                        self.send_telegram(message)

                    for alert_id in alert["ids"]:
                        self.sent_alerts_cache.append(alert_id)

                self._advance_checkpoint(hits)
                if len(hits) < 1000:
                    time.sleep(5)
            except Exception as exc:
                log_callback(f"[-] Error: {exc}")
                time.sleep(5)
