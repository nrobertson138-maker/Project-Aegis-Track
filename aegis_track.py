import os
import sys
import time
import re
import json
import hashlib
import hmac
import argparse
import urllib.request
from datetime import datetime

# CONFIGURATION PARAMETERS
LOG_FILE_PATH = "/var/log/secure"
THRESHOLD_ATTEMPTS = 5
TIME_WINDOW_SECONDS = 60
ALERT_LOG_PATH = "aegis_alerts.json"

# CLOUD VAULT PRODUCTION PARAMETERS - SECURE OS ENVIRONMENT VARIABLES
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
AWS_REGION = "us-east-2"  # Hardcoded deployment region target
AWS_BUCKET_NAME = "aegis-track-logs-nicholas"  # Hardcoded destination asset label

# REGEX PATTERNS FOR AUTHENTICATION FAILURES
FAILED_AUTH_PATTERN = re.compile(r"Failed password for .* from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
SUDO_FAILURE_PATTERN = re.compile(r"authentication failure;.*user=(?P<user>\w+)")

class AegisTracker:
    def __init__(self, local_only=False):
        self.ip_tracker = {}
        self.local_only = local_only
        
        # FIX: Ensure hostname extracts purely as a clean string text asset
        self.hostname = os.uname().nodename  
        
        print(f"[*] Aegis-Track Initialized on Node: {self.hostname}")
        print(f"[*] Monitoring: {LOG_FILE_PATH}")
        
        if not self.local_only and (not AWS_ACCESS_KEY or not AWS_SECRET_KEY):
            print("[!] Error: Cloud pipeline requested but AWS Environment Variables are missing!")
            print("[*] Falling back to local-only logging mode safety protocols.")
            self.local_only = True

        if self.local_only:
            print("[!] Running in LOCAL-ONLY mode. Cloud forwarding disabled.")
        else:
            print(f"[*] Out-of-Band Cloud Pipeline Enabled -> S3://{AWS_BUCKET_NAME}")

    def sign(self, key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def get_signature_key(self, key, date_stamp, region_name, service_name):
        k_date = self.sign(('AWS4' + key).encode('utf-8'), date_stamp)
        k_region = self.sign(k_date, region_name)
        k_service = self.sign(k_region, service_name)
        k_signing = self.sign(k_service, 'aws4_request')
        return k_signing

    def forward_to_s3(self, alert_payload, object_name):
        if self.local_only:
            return
            
        payload_bytes = json.dumps(alert_payload).encode('utf-8')
        method = 'PUT'
        service = 's3'
        
        # REGIONAL FIX: For us-east-2, host must explicitly use regional endpoints
        host = f'{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com'
        endpoint = f'https://{host}/{object_name}'
        
        t = datetime.utcnow()
        amz_date = t.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = t.strftime('%Y%m%d')
        
        # URI FIX: Canonical URI must strictly match the absolute resource path
        canonical_uri = f'/{object_name}'
        canonical_querystring = ''
        canonical_headers = f'host:{host}\nx-amz-date:{amz_date}\n'
        signed_headers = 'host;x-amz-date'
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()
        canonical_request = f"{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f"{date_stamp}/{AWS_REGION}/{service}/aws4_request"
        string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        
        signing_key = self.get_signature_key(AWS_SECRET_KEY, date_stamp, AWS_REGION, service)
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        
        authorization_header = f"{algorithm} Credential={AWS_ACCESS_KEY}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        headers = {
            'Host': host,
            'x-amz-date': amz_date,
            'Authorization': authorization_header,
            'Content-Type': 'application/json',
            'Content-Length': str(len(payload_bytes)) # Explicitly broadcast size metric
        }
        
        try:
            req = urllib.request.Request(endpoint, data=payload_bytes, headers=headers, method='PUT')
            with urllib.request.urlopen(req) as response:
                if response.status == 200:
                    print(f"[CLOUD SUCCESS] Immutable log archived -> {object_name}")
        except Exception as e:
            print(f"[CLOUD ERROR] Out-of-band pipeline degraded: {e}")

    def parse_log_line(self, line):
        current_time = time.time()
        ssh_match = FAILED_AUTH_PATTERN.search(line)
        if ssh_match:
            self.log_failure(ssh_match.group("ip"), current_time, attack_type="SSH Brute Force")
            
        sudo_match = SUDO_FAILURE_PATTERN.search(line)
        if sudo_match:
            self.log_failure(sudo_match.group("user"), current_time, attack_type="Unauthorized Sudo Attempt")

    def log_failure(self, identifier, timestamp, attack_type):
        if identifier not in self.ip_tracker:
            self.ip_tracker[identifier] = []
        self.ip_tracker[identifier].append(timestamp)
        self.ip_tracker[identifier] = [t for t in self.ip_tracker[identifier] if timestamp - t <= TIME_WINDOW_SECONDS]
        
        if len(self.ip_tracker[identifier]) >= THRESHOLD_ATTEMPTS:
            self.trigger_incident_response(identifier, attack_type)

    def trigger_incident_response(self, identifier, attack_type):
        alert_time = datetime.utcnow().isoformat() + "Z"
        unique_id = hashlib.md5(f"{alert_time}-{identifier}".encode()).hexdigest()[:8]
        
        alert_payload = {
            "timestamp": alert_time,
            "incident_id": f"AEGIS-{unique_id}",
            "origin_host": self.hostname,
            "severity": "CRITICAL",
            "attack_vector": attack_type,
            "target_identifier": identifier,
            "threshold_crossed": f"{THRESHOLD_ATTEMPTS} attempts within {TIME_WINDOW_SECONDS}s",
            "mitre_mapping": "T1110" if attack_type == "SSH Brute Force" else "T1548"
        }
        
        print(f"[CRITICAL INTERVENTION] Local alert generated for {attack_type}.")
        
        with open(ALERT_LOG_PATH, "a") as alert_file:
            alert_file.write(json.dumps(alert_payload) + "\n")
            
        # File pathing structure inside S3 separates logs dynamically by host node
        object_name = f"alerts/{self.hostname}/{datetime.utcnow().strftime('%Y/%m/%d')}/incident_{unique_id}.json"
        self.forward_to_s3(alert_payload, object_name)
        
        del self.ip_tracker[identifier]

    def watch_log(self):
        try:
            if not os.path.exists(LOG_FILE_PATH):
                print(f"[!] Error: {LOG_FILE_PATH} does not exist.")
                sys.exit(1)
            with open(LOG_FILE_PATH, "r") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    self.parse_log_line(line)
        except KeyboardInterrupt:
            print("\n[*] Aegis-Track cleanly halted.")
        except PermissionError:
            print("[!] Error: Root/Sudo privileges required.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aegis-Track Engine")
    parser.add_argument('--local-only', action='store_true', help='Disable cloud streaming architecture.')
    args = parser.parse_args()

    tracker = AegisTracker(local_only=args.local_only)
    tracker.watch_log()

