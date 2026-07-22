import os
import re
import yaml
import json
from datetime import datetime

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "log_config.yaml")

# Load configuration registry
if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        log_config = yaml.safe_load(f)
else:
    # Fallback default configuration if not found
    log_config = {
        "source_detection": [],
        "mappings": {
            "Default": {
                "username": ["log_indicators.target_user", "authentication_details.attempted_target_user"],
                "hostname": ["log_indicators.computer_name"],
                "timestamp": ["incident_details.timestamp"]
            }
        }
    }

def get_nested_value(data, path_str):
    """Safely extracts nested dict values using a dotted path."""
    parts = path_str.split('.')
    cur = data
    for p in parts:
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur

def extract_mapped_fields(data: dict) -> dict:
    """Uses configuration rules to detect the source and extract markers."""
    source_type = "Default"
    for det in log_config.get("source_detection", []):
        if det["key"] in data:
            source_type = det["source_type"]
            break
            
    mappings = log_config.get("mappings", {}).get(source_type, log_config["mappings"]["Default"])
    
    username = None
    for field in mappings.get("username", []):
        username = get_nested_value(data, field)
        if username:
            break
            
    hostname = None
    for field in mappings.get("hostname", []):
        hostname = get_nested_value(data, field)
        if hostname:
            break
            
    timestamp_str = None
    for field in mappings.get("timestamp", []):
        timestamp_str = get_nested_value(data, field)
        if timestamp_str:
            break
            
    return {
        "source_type": source_type,
        "username": str(username) if username else "Unknown",
        "hostname": str(hostname) if hostname else "Unknown",
        "timestamp_str": str(timestamp_str) if timestamp_str else "Unknown"
    }

def parse_timestamp_to_epoch(timestamp_str: str) -> int:
    """Converts ISO 8601 timestamp string to Unix Epoch integer."""
    if not timestamp_str or timestamp_str == "Unknown":
        return 0
    try:
        t_str = timestamp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(t_str)
        return int(dt.timestamp())
    except Exception:
        try:
            # Fallback for alternative millisecond or timezone formats
            t_str = timestamp_str.split(".")[0].replace("Z", "")
            dt = datetime.strptime(t_str, "%Y-%m-%dT%H:%M:%S")
            return int(dt.timestamp())
        except Exception:
            return 0

# Compile global regex objects for scanning tokens
IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
EMAIL_REGEX = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b')
DOMAIN_REGEX = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b')

EXCLUDED_EXTENSIONS = {
    '.exe', '.dll', '.txt', '.php', '.yaml', '.json', '.sys', 
    '.lnk', '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.zip', '.rar'
}

def scan_indicators(flat_string: str) -> dict:
    """Regex scans a flat string representation of JSON for forensic markers."""
    ips = list(set(IPV4_REGEX.findall(flat_string)))
    sha256s = list(set(SHA256_REGEX.findall(flat_string)))
    md5s = list(set(MD5_REGEX.findall(flat_string)))
    emails = list(set(EMAIL_REGEX.findall(flat_string)))
    
    # Filter domains to exclude pure IPs, numeric values, and file names
    all_domains = DOMAIN_REGEX.findall(flat_string)
    filtered_domains = []
    for d in all_domains:
        if IPV4_REGEX.match(d):
            continue
        ext = os.path.splitext(d.lower())[1]
        if ext in EXCLUDED_EXTENSIONS:
            continue
        if d.replace('.', '').isdigit():
            continue
        filtered_domains.append(d)
        
    domains = list(set(filtered_domains))
    
    return {
        "ips": ips,
        "sha256s": sha256s,
        "md5s": md5s,
        "emails": emails,
        "domains": domains
    }

def serialize_json_to_narrative(data: dict) -> str:
    """Recursively serializes JSON fields into structural narrative sentences."""
    lines = []
    incident_id = data.get("incident_id", "Unknown")
    lines.append(f"Incident {incident_id} details are as follows:")
    
    def recurse(d, parent_key=""):
        for k, v in sorted(d.items()):
            full_key = f"{parent_key} {k}".strip().replace("_", " ")
            if isinstance(v, dict):
                recurse(v, full_key)
            elif isinstance(v, list):
                items_str = ", ".join(str(i) for i in v)
                lines.append(f"The {full_key} lists: {items_str}.")
            elif v is not None:
                lines.append(f"The {full_key} is {v}.")
                
    recurse(data)
    return " ".join(lines)

def process_log_file(filepath: str) -> dict:
    """Parses, scans, normalizes, and serializes a raw log JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    incident_id = data.get("incident_id", os.path.basename(filepath).split("_")[0])
    
    # Map variables and parse timestamp
    mapped = extract_mapped_fields(data)
    epoch = parse_timestamp_to_epoch(mapped["timestamp_str"])
    
    # Extract indicators via flat JSON string
    flat_str = json.dumps(data)
    indicators = scan_indicators(flat_str)
    
    # Serialize to narrative
    document = serialize_json_to_narrative(data)
    
    # Extract mitre tactic and technique
    mitre_data = data.get("incident_details", {}).get("mitre_att&ck", {})
    tactic = mitre_data.get("tactic", "Unknown") if mitre_data else "Unknown"
    technique = mitre_data.get("technique", "Unknown") if mitre_data else "Unknown"
    
    # Pack flat metadata fields for ChromaDB
    metadata = {
        "incident_id": incident_id,
        "source_type": mapped["source_type"],
        "username": mapped["username"],
        "hostname": mapped["hostname"],
        "timestamp_str": mapped["timestamp_str"],
        "timestamp_epoch": epoch,
        "tactic": tactic,
        "technique": technique,
        "ips": ",".join(indicators["ips"]),
        "sha256s": ",".join(indicators["sha256s"]),
        "md5s": ",".join(indicators["md5s"]),
        "emails": ",".join(indicators["emails"]),
        "domains": ",".join(indicators["domains"])
    }
    
    return {
        "id": incident_id,
        "document": document,
        "metadata": metadata
    }
