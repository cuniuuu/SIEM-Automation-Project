class CaseBuilder:
    def build(self, alert_source, alert_summary, metadata_record, env_label):
        metadata = (metadata_record or {}).get("metadata", {})
        return {
            "title": alert_summary.get("rule"),
            "environment": env_label,
            "rule_id": alert_source.get("kibana.alert.rule.rule_id"),
            "severity": metadata.get("severity") or alert_source.get("kibana.alert.rule.severity") or "medium",
            "risk_score": alert_source.get("kibana.alert.rule.risk_score") or metadata.get("risk_score") or 0,
            "owner": metadata.get("owner", {}),
            "playbook": metadata.get("response_playbook", {}),
            "entities": {
                "host": alert_source.get("host", {}).get("name") or alert_source.get("host.name"),
                "user": alert_summary.get("user"),
                "source_ip": alert_source.get("source", {}).get("ip") or alert_source.get("source.ip"),
                "process": alert_summary.get("proc_name"),
            },
            "evidence": alert_summary.get("evidence"),
            "source_event": {
                "timestamp": alert_summary.get("last_time"),
                "alert_ids": alert_summary.get("ids", []),
            },
            "status": "new",
        }
