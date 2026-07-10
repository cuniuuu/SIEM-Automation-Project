from datetime import datetime, timezone
from uuid import uuid4


class CaseStore:
    def __init__(self, es_client, env_label, index_prefix="siem-soar"):
        self.es = es_client
        self.case_index = f"{index_prefix}-cases-{env_label.lower()}"
        self.audit_index = f"{index_prefix}-audit-{env_label.lower()}"

    def create_case(self, case_payload):
        case_id = case_payload.get("case_id") or f"case-{uuid4()}"
        document = {
            **case_payload,
            "case_id": case_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": case_payload.get("status", "new"),
        }
        self.es.index(index=self.case_index, id=case_id, document=document)
        return document

    def write_audit(self, event_type, payload):
        document = {
            "event_type": event_type,
            "payload": payload,
            "@timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.es.index(index=self.audit_index, document=document)
        return document
