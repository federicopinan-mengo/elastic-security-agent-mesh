#!/usr/bin/env python3
import json
import os
import sys
from datetime import UTC, datetime

try:
    import requests
except ImportError:
    print("ERROR: 'requests' package required. Install with: pip install requests")
    sys.exit(1)

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
INDEX_NAME = "kb-mitre-attack"


def es_headers():
    api_key = os.environ.get("ES_API_KEY")
    if not api_key:
        print("ERROR: ES_API_KEY environment variable not set.")
        sys.exit(1)
    return {
        "Content-Type": "application/x-ndjson",
        "Authorization": f"ApiKey {api_key}",
    }


def main():
    es_url = os.environ.get("ELASTIC_CLOUD_URL")
    if not es_url:
        print("ERROR: ELASTIC_CLOUD_URL environment variable not set.")
        sys.exit(1)

    print(f"Downloading MITRE ATT&CK STIX data from {MITRE_URL}...")
    resp = requests.get(MITRE_URL, timeout=60)
    if not resp.ok:
        print(f"Failed to download MITRE STIX: {resp.status_code}")
        sys.exit(1)

    stix_data = resp.json()
    objects = stix_data.get("objects", [])
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    bulk_body = ""
    count = 0

    for obj in objects:
        if obj.get("type") not in [
            "attack-pattern",
            "course-of-action",
            "intrusion-set",
            "malware",
            "tool",
        ]:
            continue

        obj_id = obj.get("id")
        name = obj.get("name", "Unknown")
        description = obj.get("description", "")
        obj_type = obj.get("type")

        external_references = obj.get("external_references", [])
        mitre_id = ""
        for ref in external_references:
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")
                break

        if mitre_id:
            title = f"{mitre_id}: {name}"
        else:
            title = name

        doc = {
            "title": title,
            "content": f"Name: {name}\nType: {obj_type}\nMITRE ID: {mitre_id}\n\nDescription:\n{description}",
            "semantic_summary": f"MITRE ATT&CK {obj_type} {title}. {description[:500]}",
            "category": "mitre-attack",
            "source": "mitre",
            "tags": ["mitre", obj_type],
            "created_at": now,
            "updated_at": now,
            "metadata": {"mitre_id": mitre_id, "type": obj_type, "name": name, "stix_id": obj_id},
        }

        bulk_body += json.dumps({"index": {"_id": obj_id}}) + "\n"
        bulk_body += json.dumps(doc) + "\n"
        count += 1

        if count % 500 == 0:
            print(f"Indexing {count} MITRE objects...")
            post_bulk(es_url, bulk_body)
            bulk_body = ""

    if bulk_body:
        post_bulk(es_url, bulk_body)

    print(f"Successfully seeded {count} MITRE ATT&CK objects into {INDEX_NAME}.")


def post_bulk(es_url, bulk_body):
    url = f"{es_url}/{INDEX_NAME}/_bulk"
    resp = requests.post(url, headers=es_headers(), data=bulk_body, timeout=30)
    if not resp.ok:
        print(f"Bulk indexing failed: {resp.status_code} - {resp.text[:200]}")


if __name__ == "__main__":
    main()
