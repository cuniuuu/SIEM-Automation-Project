# SOAR Minimal Deployment

## Muc tieu

Trien khai SOAR toi thieu tren chinh may dang chua repo hien tai.

Flow:

`Winlogbeat/Sysmon -> Elasticsearch/Kibana -> AlertMonitor -> SOAR case/audit -> Telegram`

## May chua repo hien tai can co

- Python 3.10+
- Repo nay
- Elastic va Kibana da truy cap duoc qua `.env`

Package:

```powershell
pip install -r requirements.txt
```

## Bien moi truong can co trong `scripts/.env`

```dotenv
ELASTIC_HOST=https://<elastic-ip>:9200
KIBANA_HOST=http://<kibana-ip>:5601
ELASTIC_USER=elastic
ELASTIC_PASS=<password>
TELEGRAM_TOKEN=<bot_token>
TELEGRAM_CHAT_ID=<chat_id>
INDEX_PROD=.internal.alerts-security.alerts-default-*
INDEX_DEV=.internal.alerts-security.alerts-detection-dev-*
KIBANA_SPACE_PROD=default
KIBANA_SPACE_DEV=detection-dev
```

## SOAR da duoc them gi

- `scripts/alert.py`
  - van doc alert tu Elastic nhu cu
  - them case creation
  - them audit log
  - van gui Telegram
- `scripts/soar/metadata_loader.py`
  - map `rule_id` sang metadata trong repo
- `scripts/soar/case_builder.py`
  - chuan hoa alert thanh case
- `scripts/soar/playbook_runner.py`
  - chay playbook toi thieu
- `scripts/soar/action_executor.py`
  - ghi audit + gui Telegram
- `scripts/soar/case_store.py`
  - luu case va audit vao Elasticsearch

## Index moi se duoc tao

- `siem-soar-cases-dev` hoac `siem-soar-cases-prod`
- `siem-soar-audit-dev` hoac `siem-soar-audit-prod`

## Cach chay

### Tu GUI

```powershell
cd scripts
python main.py
```

- Bat `THREAT SCAN`
- Khi alert moi xuat hien:
  - Telegram van gui
  - case duoc luu vao index SOAR
  - audit event duoc luu vao index SOAR

### Kiem tra tren Elasticsearch

Tim case:

```json
GET /siem-soar-cases-*/_search
{
  "size": 10,
  "sort": [
    { "created_at": "desc" }
  ]
}
```

Tim audit:

```json
GET /siem-soar-audit-*/_search
{
  "size": 20,
  "sort": [
    { "@timestamp": "desc" }
  ]
}
```

## Port can mo

- Tu may repo/SOAR toi Elasticsearch: `9200/tcp`
- Tu may repo/SOAR toi Kibana: `5601/tcp`
- Tu may repo/SOAR ra Internet de gui Telegram: `443/tcp`

## Checklist victim

Chi can dung 4 thu sau:

- Sysmon
- Winlogbeat
- PowerShell Script Block Logging
- Process Creation Logging

Neu da co 4 thu nay va log dang do ve Elastic dung field, thi victim da san sang cho SOAR toi thieu.
