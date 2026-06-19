import os
import yaml
import json
import requests
import shutil
import subprocess
import threading
from tkinter import messagebox, filedialog

class RuleManager:
    def __init__(self, rules_dir, log_func):
        self.rules_dir = rules_dir
        self.log_func = log_func
        self.env_name, self.space_id = self._detect_environment()
        self.log_func(f"[*] Rule Manager Active: {self.env_name} (Space: {self.space_id})")
        self.trash_dir = "trash"
        os.makedirs(self.trash_dir, exist_ok=True)
        self.all_rules = []

    def _detect_environment(self):
        try:
            branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], stderr=subprocess.STDOUT).decode().strip()
        except Exception: 
            branch = "dev"
        if branch == "main": 
            return "main", "default"
        else: 
            return branch, "detection-dev"

    def _parse_rule_file(self, filepath):
        """Hàm trợ giúp đọc ID từ cả file YAML và JSON dựa theo phần mở rộng."""
        f_lower = filepath.lower()
        if f_lower.endswith(('.yml', '.yaml')):
            with open(filepath, encoding='utf-8') as f:
                d = yaml.safe_load(f)
                if d and isinstance(d, dict):
                    return d.get('id'), d.get('title', 'N/A'), 'OFF' if str(d.get('status', '')).lower() == 'deprecated' else 'ON'
        elif f_lower.endswith('.json'):
            with open(filepath, encoding='utf-8') as f:
                d = json.load(f)
                if d:
                    rule_obj = d[0] if isinstance(d, list) else d
                    rid = rule_obj.get('id') or rule_obj.get('rule_id')
                    title = rule_obj.get('name') or rule_obj.get('title') or 'N/A'
                    status = 'ON' if rule_obj.get('enabled', True) else 'OFF'
                    return rid, title, status
        return None, None, None

    def on_mode_change(self, search_var, drop_frame):
        search_var.set("")
        drop_frame.pack_forget()

    def filter_logic(self, term, mode, tree, drop_frame):
        term = term.lower().strip()
        if not term:
            drop_frame.pack_forget()
            return
        tree.delete(*tree.get_children())
        if mode == "Folder Mode":
            seen = set()
            for r in self.all_rules:
                folder = os.path.dirname(r['path'])
                fname = os.path.basename(folder)
                if term in fname.lower() and folder not in seen:
                    tree.insert("", "end", values=("DIR", f"Folder: {fname}"), tags=(folder,))
                    seen.add(folder)
        else:
            for r in self.all_rules:
                if term in r['file'].lower() or term in r['title'].lower():
                    tree.insert("", "end", values=(r['status'], r['title']), tags=(r['path'],))
        if tree.get_children(): 
            drop_frame.pack(fill="x", pady=(5, 0))

    def delete(self, tree, mode, refresh_callback):
        sel = tree.selection()
        if not sel: 
            return
        path = tree.item(sel[0], "tags")[0]
        name = os.path.basename(path)
        if not messagebox.askyesno("Confirm", f"Delete {mode}: {name}?"): 
            return
        self.log_func(f"[*] Bulk Deleting {mode}: {name}...")

        def _delete_task():
            current_branch, space_id = self._detect_environment()
            host = os.getenv('KIBANA_HOST', '').rstrip('/')
            api_endpoint = f"{host}/api/detection_engine/rules/_bulk_delete" if space_id == "default" else f"{host}/s/{space_id}/api/detection_engine/rules/_bulk_delete"
            try:
                targets = []
                if mode == "Folder Mode":
                    for r, _, fs in os.walk(path):
                        for f in fs:
                            if f.lower().endswith(('.yml', '.yaml', '.json')): 
                                targets.append(os.path.join(r, f))
                else: 
                    targets = [path]
                
                payload_full = []
                for p in targets:
                    try:
                        rid, _, _ = self._parse_rule_file(p)
                        if rid: 
                            payload_full.append({"rule_id": rid})
                    except: 
                        continue
                        
                if not payload_full: 
                    return self.log_func("[-] No valid Rule IDs found.")
                    
                chunk_size = 100
                chunks = [payload_full[i:i + chunk_size] for i in range(0, len(payload_full), chunk_size)]
                success_on_siem = True
                
                for chunk in chunks:
                    res = requests.post(
                        api_endpoint, 
                        auth=(os.getenv('ELASTIC_USER'), os.getenv('ELASTIC_PASS')), 
                        headers={"kbn-xsrf": "true", "Content-Type": "application/json"}, 
                        json=chunk, 
                        verify=False, 
                        timeout=60
                    )
                    if res.status_code != 200: 
                        success_on_siem = False
                        break
                        
                if success_on_siem:
                    dest = os.path.join(self.trash_dir, f"{name}_dir" if mode == "Folder Mode" else name)
                    if os.path.exists(dest): 
                        shutil.rmtree(dest) if os.path.isdir(dest) else os.remove(dest)
                    shutil.move(path, dest)
                    subprocess.run(["git", "add", "."], check=True)
                    subprocess.run(["git", "commit", "-m", f"SOC-GUI: Deleted {name}"], check=True)
                    subprocess.run(["git", "push", "origin", current_branch], check=True)
                    self.log_func(f"SUCCESS: Removed and Git synced.")
            except Exception as e: 
                self.log_func(f"[-] Critical Error: {e}")
            finally: 
                refresh_callback()
                
        threading.Thread(target=_delete_task, daemon=True).start()

    def sync_audit(self):
        def _task():
            self.load_rules_data()
            _, space_id = self._detect_environment()
            host = os.getenv('KIBANA_HOST', '').rstrip('/')
            api = f"{host}{'' if space_id == 'default' else f'/s/{space_id}'}/api/detection_engine/rules/_find"
            
            try:
                self.log_func("[*] Đang đối soát dữ liệu Repo và Kibana...")
                
                kibana_ids = set()
                page = 1
                per_page = 100
                
                while True:
                    res = requests.get(
                        api, 
                        auth=(os.getenv('ELASTIC_USER'), os.getenv('ELASTIC_PASS')),
                        headers={"kbn-xsrf": "true"}, 
                        params={"page": page, "per_page": per_page}, 
                        verify=False, 
                        timeout=20
                    )
                    if res.status_code != 200:
                        self.log_func(f"[-] Lỗi kết nối API Kibana (Page {page}): HTTP {res.status_code}")
                        return
                        
                    payload = res.json()
                    kibana_data = payload.get('data', [])
                    if not kibana_data:
                        break
                    
                    for r in kibana_data:
                        rid = r.get('rule_id') or r.get('id')
                        if rid:
                            kibana_ids.add(rid)
                    
                    total = payload.get('total', 0)
                    if page * per_page >= total:
                        break
                    page += 1

                repo_map = {}
                for r in self.all_rules:
                    try:
                        rid, _, _ = self._parse_rule_file(r['path'])
                        if rid:
                            repo_map[rid] = r['file']
                    except:
                        continue
                        
                repo_ids = set(repo_map.keys())
                only_in_repo = repo_ids - kibana_ids
                only_in_kibana = kibana_ids - repo_ids
                
                self.log_func(f"[!] Thống kê chuẩn: Repo({len(repo_ids)}) | Kibana({len(kibana_ids)})")
                
                if not only_in_repo and not only_in_kibana:
                    self.log_func("[+] Đồng bộ hoàn toàn 100%")
                else:
                    self.log_func(f"--- CHI TIẾT SAI LỆCH ({len(only_in_repo) + len(only_in_kibana)}) ---")
                    if only_in_repo:
                        self.log_func(f"[*] Có ở Repo nhưng chưa có trên Kibana ({len(only_in_repo)}):")
                        for rid in only_in_repo:
                            self.log_func(f"  + {repo_map[rid]}")
                    if only_in_kibana:
                        self.log_func(f"[*] Có trên Kibana nhưng đã mất trong Repo ({len(only_in_kibana)}):")
                        for rid in only_in_kibana:
                            self.log_func(f"  - ID: {rid}")
            except Exception as e:
                self.log_func(f"[-] Lỗi đối soát hệ thống: {str(e)}")
                
        threading.Thread(target=_task, daemon=True).start()

    def restore(self, mode, refresh_callback):
        p = filedialog.askdirectory(initialdir=self.trash_dir) if mode == "Folder Mode" else filedialog.askopenfilename(initialdir=self.trash_dir, filetypes=[("Detection Rules", "*.yml *.yaml *.json")])
        if not p: 
            return
        self.log_func(f"[*] Restoring {os.path.basename(p)}...")
        try:
            dest = os.path.join(self.rules_dir, os.path.basename(p).replace("_dir", ""))
            shutil.move(p, dest)
            self.log_func(f"[+] Restored.")
            refresh_callback()
        except Exception as e: 
            self.log_func(f"[-] Restore error: {e}")

    def load_rules_data(self):
        self.all_rules.clear()
        for root, _, files in os.walk(self.rules_dir):
            for f in files:
                p = os.path.join(root, f)
                try:
                    rid, title, status = self._parse_rule_file(p)
                    if rid:
                        self.all_rules.append({
                            "path": p, 
                            "file": f, 
                            "title": title, 
                            "status": status
                        })
                except: 
                    pass

    def set_status(self, status, tree, refresh_callback):
        for item in tree.selection():
            path = tree.item(item, "tags")[0]
            if os.path.isdir(path): 
                continue
            try:
                if path.lower().endswith(('.yml', '.yaml')):
                    with open(path, encoding='utf-8') as f: 
                        data = yaml.safe_load(f)
                    data['status'] = status
                    with open(path, 'w', encoding='utf-8') as f: 
                        yaml.dump(data, f, allow_unicode=True, sort_keys=False)
                elif path.lower().endswith('.json'):
                    with open(path, encoding='utf-8') as f:
                        data = json.load(f)
                    
                    # Update thuộc tính trạng thái kích hoạt rule trên Kibana JSON Schema
                    if isinstance(data, list):
                        for rule_item in data:
                            rule_item['enabled'] = True if status.upper() == 'ON' else False
                    else:
                        data['enabled'] = True if status.upper() == 'ON' else False
                        
                    with open(path, 'w', encoding='utf-8') as f:
                        json.dump(data, f, ensure_ascii=False, indent=2)
                        
                self.log_func(f"Updated: {os.path.basename(path)} → {status.upper()}")
            except: 
                pass
        refresh_callback()