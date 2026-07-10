# Victim Prerequisites

## Bat buoc

- Sysmon
- Winlogbeat
- PowerShell Script Block Logging
- Process Creation Logging

## Yeu cau ket noi

- Victim phai gui duoc log ve Elasticsearch
- Neu dung Winlogbeat gui truc tiep: mo `9200/tcp` outbound tu victim toi Elastic
- Neu sau nay them Logstash: dung `5044/tcp`

## Field toi thieu nen co trong log

- `@timestamp`
- `host.name`
- `user.name`
- `process.name`
- `process.command_line`
- `process.parent.name`
- `source.ip`
- `registry.path`
- `powershell.file.script_block_text`

## Kiem tra nhanh

- Co event process creation len Elasticsearch
- Co event PowerShell logging len Elasticsearch
- Rule tren Kibana da tao alert duoc

Neu 3 dong tren dung, victim da dat muc san sang cho lab SOAR toi thieu.
