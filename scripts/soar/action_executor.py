class ActionExecutor:
    def __init__(self, send_telegram, case_store):
        self.send_telegram = send_telegram
        self.case_store = case_store

    def execute(self, case_doc, telegram_message, log_callback):
        self.case_store.write_audit("case_created", case_doc)
        self.send_telegram(telegram_message)
        self.case_store.write_audit(
            "notification_sent",
            {
                "case_id": case_doc["case_id"],
                "channel": "telegram",
                "rule_id": case_doc["rule_id"],
            },
        )
        log_callback(
            f"[SOAR] Case created: {case_doc['case_id']} | "
            f"Playbook: {case_doc.get('playbook', {}).get('id', 'manual')}"
        )
