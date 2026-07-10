class PlaybookRunner:
    def __init__(self, case_builder, case_store, action_executor):
        self.case_builder = case_builder
        self.case_store = case_store
        self.action_executor = action_executor

    def run(self, alert_source, alert_summary, metadata_record, env_label, telegram_message, log_callback):
        case_payload = self.case_builder.build(alert_source, alert_summary, metadata_record, env_label)
        case_doc = self.case_store.create_case(case_payload)
        self.action_executor.execute(case_doc, telegram_message, log_callback)
        return case_doc
