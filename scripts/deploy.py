import subprocess, requests, sys, io, os, shutil, yaml, json

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# --- CONFIGURATION ---
URL = os.getenv('KIBANA_URL') 
USER = os.getenv('ELASTIC_USERNAME')
PASS = os.getenv('ELASTIC_PASSWORD')
SPACE_ID = os.getenv('KIBANA_SPACE')

RULES_INPUT = 'rules/'
NDJSON_OUTPUT = 'rules/windows_rules.ndjson'

def get_sigma_path():
    sigma_path = shutil.which("sigma")
    if sigma_path: return f'"{sigma_path}"'
    sigma_exe = os.path.join(os.path.dirname(sys.executable), "Scripts", "sigma.exe")
    return f'"{sigma_exe}"' if os.path.exists(sigma_exe) else "sigma"

def process_rules():
    print("[*] Scan YAML files for deprecated status...")
    deprecated_ids = set()
    for root, _, files in os.walk(RULES_INPUT):
        for file in files:
            if not file.endswith(('.yml', '.yaml')): continue   
            path = os.path.join(root, file)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                if not data: continue
                
                rule_id = data.get('id')
                if rule_id and str(data.get('status', '')).lower() == 'deprecated':
                    deprecated_ids.add(str(rule_id).lower())
                    print(f"  [-] Registered Deprecated ID (Sigma): {rule_id} ({file})")
                        
            except Exception as e:
                print(f"  [-] Error reading {file}: {e}")
    return deprecated_ids

def patch_ndjson(deprecated_ids):
    print(f"[*] Patching NDJSON from Sigma-cli for real-time monitoring (interval: 1m)...")
    
    if not os.path.exists(NDJSON_OUTPUT):
        print("[-] NDJSON file not found to patch.")
        return False
        
    patched_lines = []

    with open(NDJSON_OUTPUT, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip(): continue
            try:
                rule = json.loads(line)
                
                # Ép cấu hình chạy Real-time khắt khe của SOC cho Sigma Rules
                rule['interval'] = "1m"
                rule['from'] = "now-120s"
                
                kibana_id = str(rule.get('id', '')).lower()
                kibana_rule_id = str(rule.get('rule_id', '')).lower()
                
                if kibana_id in deprecated_ids or kibana_rule_id in deprecated_ids:
                    rule['enabled'] = False
                    print(f"  [!] Disabled patched rule: {rule.get('name')}")
                
                patched_lines.append(json.dumps(rule, ensure_ascii=False))
            except Exception as e:
                print(f"  [-] Line parsing error: {e}")

    with open(NDJSON_OUTPUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(patched_lines) + '\n')
    print("[+] Patching Sigma rules completed.")
    return True

def append_custom_json_rules(deprecated_ids):
    print("[*] Scanning and appending Native JSON Threshold Rules...")
    custom_lines = []
    
    for root, _, files in os.walk(RULES_INPUT):
        for file in files:
            if not file.endswith('.json'): continue
            path = os.path.join(root, file)
            
            # Bỏ qua chính file output nếu bạn lỡ đặt trùng trong thư mục rules
            if os.path.abspath(path) == os.path.abspath(NDJSON_OUTPUT): continue
            
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    rule = json.load(f)
                
                if not rule: continue
                
                # Bắt buộc ép cấu hình đồng bộ với hệ thống Real-time
                rule['interval'] = "1m"
                rule['from'] = "now-120s"
                
                # Check trạng thái deprecated nếu file JSON có định nghĩa hoặc map ID
                kibana_id = str(rule.get('id', '')).lower()
                kibana_rule_id = str(rule.get('rule_id', '')).lower()
                if str(rule.get('status', '')).lower() == 'deprecated' or kibana_id in deprecated_ids or kibana_rule_id in deprecated_ids:
                    rule['enabled'] = False
                    print(f"  [-] Native JSON Rule Target OFF (deprecated): {file}")
                
                custom_lines.append(json.dumps(rule, ensure_ascii=False))
                print(f"  [+] Integrated Native JSON Rule: {rule.get('name')} ({file})")
                
            except Exception as e:
                print(f"  [-] Error processing JSON rule {file}: {e}")
                
    if custom_lines:
        # Ghi nối tiếp (Mode 'a' - Append) vào file NDJSON hiện tại
        with open(NDJSON_OUTPUT, 'a', encoding='utf-8') as f:
            f.write('\n'.join(custom_lines) + '\n')
        print(f"[+] Successfully appended {len(custom_lines)} custom JSON rules to NDJSON.")
    else:
        print("[*] No custom JSON rules found to append.")

def deploy():
    # 1. Quét trạng thái từ file nguồn YAML trước
    dep_ids = process_rules()
    
    # 2. Biên dịch thông qua Sigma-cli (Tạo mới file NDJSON chứa các rule gốc của Sigma)
    cmd = f'{get_sigma_path()} convert -t lucene -p ecs_windows -f siem_rule_ndjson "{RULES_INPUT}" --skip-unsupported -o "{NDJSON_OUTPUT}"'
    print("[*] Converting Sigma rules via sigma-cli...")
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[-] Conversion failed. Error: {result.stderr}")
        return
    
    # 3. Tiến hành tinh chỉnh thuộc tính của nhóm rule vừa convert từ Sigma
    if not patch_ndjson(dep_ids):
        return
        
    # 4. ĐỌC VÀ NỐI THẲNG THRESHOLD JSON RULES VÀO CUỐI FILE NDJSON
    append_custom_json_rules(dep_ids)
        
    # 5. Thực hiện API Request để đẩy gói tổng hợp lên Kibana
    api = f"{URL}{'' if SPACE_ID == 'default' else f'/s/{SPACE_ID}'}/api/detection_engine/rules/_import"
    print(f"[*] Deploying integrated NDJSON package to Space [{SPACE_ID}]...")
    
    try:
        with open(NDJSON_OUTPUT, 'rb') as f:
            res = requests.post(
                api, 
                headers={"kbn-xsrf": "true"}, 
                auth=(USER, PASS),
                files={'file': ('rules.ndjson', f, 'application/x-ndjson')},
                params={"overwrite": "true"}
            )
        if res.status_code == 200:
            print("SUCCESS! All Sigma and Native Threshold JSON rules deployed and optimized.")
        else:
            print(f"ERROR ({res.status_code}): {res.text}")
    except Exception as e:
        print(f"[-] Connection to Kibana failed: {e}")

if __name__ == "__main__":
    deploy()