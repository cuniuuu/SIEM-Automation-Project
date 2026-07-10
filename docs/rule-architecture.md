# Rule Architecture

## Muc tieu

Chuan hoa kho rules theo 3 lop:

1. Taxonomy thu muc de tim kiem, review va phan quyen de hon.
2. Metadata van hanh de phuc vu tuning, incident response, SOAR va bao tri.
3. Template + schema de CI/CD co the validate chat luong rules.

## Cau truc thu muc de xuat

```text
rules/
  windows/
    credential_access/
      authentication/
        bruteforce/
          threshold-windows-brute-force.json
          threshold-windows-invalid-user-brute-force.json
      process_creation/
        proc_creation_win_reg_lsa_ppl_protection_disabled.yml
        proc_creation_win_rundll32_process_dump_via_comsvcs.yml
        proc_creation_win_susp_lsass_dmp_cli_keywords.yml
    defense_evasion/
      process_creation/
        proc_creation_win_certutil_download.yml
        proc_creation_win_netsh_fw_disable.yml
        proc_creation_win_rundll32_susp_activity.yml
        proc_creation_win_susp_eventlog_clear.yml
      registry/
        registry_set_windows_defender_tamper.yml
    discovery/
      process_creation/
        proc_creation_win_whoami_priv_discovery.yml
    execution/
      process_creation/
        proc_creation_win_powershell_encode.yml
    persistence/
      process_creation/
        proc_creation_win_net_user_add.yml
templates/
  rule_template_sigma.yml
  rule_template_threshold.json
schemas/
  rule_metadata.schema.json
```

## Nguyen tac dat thu muc

- Cap 1: `platform` nhu `windows`, `linux`, `cloud`, `identity`, `network`.
- Cap 2: `use_case` hoac ATT&CK tactic chinh nhu `credential_access`, `discovery`, `execution`.
- Cap 3: `telemetry category` nhu `process_creation`, `authentication`, `registry`, `dns`, `proxy`.
- Ten file:
  - Sigma: giu ten ky thuat ro rang, on dinh.
  - JSON threshold / query rule: uu tien dat theo `rule_id`.

## Metadata contract

Metadata van hanh nen duoc dat trong:

- Sigma YAML: truong `x_metadata`
- Native Kibana JSON rule: truong `metadata`

Schema tham chieu: `schemas/rule_metadata.schema.json`

### Cac truong can co

- `owner`: doi/nhom chiu trach nhiem rule.
- `status`: `draft`, `testing`, `production`, `deprecated`.
- `severity`: muc nghiem trong van hanh.
- `risk_score`: diem rui ro de dong bo voi SIEM.
- `data_sources`: nguon log bat buoc de rule hoat dong dung.
- `log_requirements`: field quan trong can co trong event.
- `false_positive_scenarios`: cac boi canh hop le co the gay canh bao.
- `tuning_notes`: cach giam nhieu.
- `response_playbook`: playbook se goi khi dua vao SOAR.
- `validation`: thong tin test case, sample log, expected behavior.
- `review`: owner ky thuat, ngay review, SLA review.

## Quy uoc vong doi rule

- `draft`: moi tao, chua test tren data that.
- `testing`: da deploy sandbox/dev, dang tuning.
- `production`: da duoc phe duyet va co owner ro rang.
- `deprecated`: ngung dung, chi giu de audit / tham chieu.

Trang thai nay nen duoc quan ly o metadata. Truong Sigma `status` van co the giu de tuong thich voi sigma-cli, nhung khong nen la nguon su that duy nhat cho vong doi van hanh.

## Huong tich hop voi SOAR

Metadata moi cho phep mapping tu detection sang orchestration:

- `response_playbook.id`: playbook duoc goi.
- `response_playbook.auto_actions`: danh sach hanh dong tu dong hoac can phe duyet.
- `triage.enrichment_queries`: cac truy van enrichment co san.
- `triage.entities`: user, host, source.ip, process.name.

Khi xay SOAR, engine chi can doc metadata theo rule ID de quyet dinh cach triage va response.

## Lo trinh nen lam tiep

1. Bo sung metadata vao toan bo rules hien tai theo schema.
2. Viet validator Python de fail CI neu thieu owner, review, response_playbook hoac data source.
3. Tach exception/suppression khoi rule goc thanh mot thu muc cau hinh rieng.
4. Them rule catalog dashboard tu metadata de quan ly quality va coverage.
