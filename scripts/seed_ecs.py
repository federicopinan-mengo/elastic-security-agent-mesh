#!/usr/bin/env python3
import csv
import json
import os
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("ERROR: 'requests' package required. Install with: pip install requests")
    sys.exit(1)

ECS_CSV_URL = "https://raw.githubusercontent.com/elastic/ecs/main/generated/csv/fields.csv"
INDEX_NAME = "kb-ecs-schema"

def es_headers():
    api_key = os.environ.get('ES_API_KEY')
    if not api_key:
        print("ERROR: ES_API_KEY environment variable not set.")
        sys.exit(1)
    return {
        "Content-Type": "application/x-ndjson",
        "Authorization": f"ApiKey {api_key}",
    }

def main():
    es_url = os.environ.get('ELASTIC_CLOUD_URL')
    if not es_url:
        print("ERROR: ELASTIC_CLOUD_URL environment variable not set.")
        sys.exit(1)

    print(f"Downloading ECS Schema from {ECS_CSV_URL}...")
    resp = requests.get(ECS_CSV_URL, timeout=30)
    if not resp.ok:
        print(f"Failed to download ECS Schema: {resp.status_code}")
        sys.exit(1)

    csv_reader = csv.DictReader(resp.text.splitlines())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    bulk_body = ""
    count = 0
    for row in csv_reader:
        if not row.get("Field"):
            continue
        
        field_name = row["Field"]
        description = row.get("Description", "")
        type_ = row.get("Type", "")
        level = row.get("Level", "")
        
        doc = {
            "title": f"ECS Field: {field_name}",
            "content": f"Field: {field_name}\nType: {type_}\nLevel: {level}\nDescription: {description}",
            "semantic_summary": f"ECS field {field_name} of type {type_}. {description}",
            "category": "ecs-schema",
            "source": "elastic",
            "tags": ["ecs", type_, level],
            "created_at": now,
            "updated_at": now,
            "metadata": {
                "field": field_name,
                "type": type_,
                "level": level,
                "description": description
            }
        }
        
        bulk_body += json.dumps({"index": {"_id": field_name}}) + "\n"
        bulk_body += json.dumps(doc) + "\n"
        count += 1
        
        if count % 1000 == 0:
            print(f"Indexing {count} ECS fields...")
            post_bulk(es_url, bulk_body)
            bulk_body = ""

    if bulk_body:
        post_bulk(es_url, bulk_body)
    
    print(f"Successfully seeded {count} ECS fields into {INDEX_NAME}.")

def post_bulk(es_url, bulk_body):
    url = f"{es_url}/{INDEX_NAME}/_bulk"
    resp = requests.post(url, headers=es_headers(), data=bulk_body, timeout=30)
    if not resp.ok:
        print(f"Bulk indexing failed: {resp.status_code} - {resp.text[:200]}")

if __name__ == "__main__":
    main()
