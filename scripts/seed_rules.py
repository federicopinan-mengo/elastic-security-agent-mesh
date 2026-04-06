#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("ERROR: 'requests' package required. Install with: pip install requests")
    sys.exit(1)

INDEX_NAME = "kb-detection-rules"

def kibana_headers():
    api_key = os.environ.get('KIBANA_API_KEY')
    if not api_key:
        print("ERROR: KIBANA_API_KEY environment variable not set.")
        sys.exit(1)
    return {
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
        "Authorization": f"ApiKey {api_key}",
    }

def es_headers():
    api_key = os.environ.get('ES_API_KEY')
    if not api_key:
        print("ERROR: ES_API_KEY environment variable not set.")
        sys.exit(1)
    return {
        "Content-Type": "application/x-ndjson",
        "Authorization": f"ApiKey {api_key}",
    }

def kibana_base_url():
    base = os.environ.get("KIBANA_URL", "").rstrip("/")
    if not base:
        print("ERROR: KIBANA_URL environment variable not set.")
        sys.exit(1)
    space = os.environ.get("KIBANA_SPACE", "").strip()
    if space and space != "default":
        return f"{base}/s/{space}"
    return base

def main():
    es_url = os.environ.get('ELASTIC_CLOUD_URL')
    if not es_url:
        print("ERROR: ELASTIC_CLOUD_URL environment variable not set.")
        sys.exit(1)

    kbn_url = kibana_base_url()
    
    print(f"Fetching detection rules from Kibana ({kbn_url})...")
    # Fetching all rules, using a large per_page
    rules_url = f"{kbn_url}/api/detection_engine/rules/_find?per_page=10000"
    resp = requests.get(rules_url, headers=kibana_headers(), timeout=60)
    
    if not resp.ok:
        print(f"Failed to fetch rules: {resp.status_code} - {resp.text[:200]}")
        sys.exit(1)
        
    data = resp.json()
    rules = data.get("data", [])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    bulk_body = ""
    count = 0

    for rule in rules:
        rule_id = rule.get("id", "")
        name = rule.get("name", "Unknown")
        description = rule.get("description", "")
        severity = rule.get("severity", "")
        risk_score = rule.get("risk_score", 0)
        tags = rule.get("tags", [])
        
        doc = {
            "title": f"Detection Rule: {name}",
            "content": f"Name: {name}\nSeverity: {severity}\nRisk Score: {risk_score}\n\nDescription:\n{description}",
            "semantic_summary": f"Security detection rule '{name}'. Severity: {severity}. {description}",
            "category": "detection-rule",
            "source": "kibana",
            "tags": tags,
            "created_at": now,
            "updated_at": now,
            "metadata": {
                "rule_id": rule_id,
                "name": name,
                "severity": severity,
                "risk_score": risk_score,
                "enabled": rule.get("enabled", False),
                "author": rule.get("author", [])
            }
        }
        
        bulk_body += json.dumps({"index": {"_id": rule_id}}) + "\n"
        bulk_body += json.dumps(doc) + "\n"
        count += 1
        
        if count % 500 == 0:
            print(f"Indexing {count} Detection Rules...")
            post_bulk(es_url, bulk_body)
            bulk_body = ""

    if bulk_body:
        post_bulk(es_url, bulk_body)
        
    print(f"Successfully seeded {count} Detection Rules into {INDEX_NAME}.")

def post_bulk(es_url, bulk_body):
    url = f"{es_url}/{INDEX_NAME}/_bulk"
    resp = requests.post(url, headers=es_headers(), data=bulk_body, timeout=30)
    if not resp.ok:
        print(f"Bulk indexing failed: {resp.status_code} - {resp.text[:200]}")

if __name__ == "__main__":
    main()
