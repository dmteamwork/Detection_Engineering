import requests
import os
import tomllib
import json

BASE_URL = "https://my-deployment-596fe6.kb.europe-west1.gcp.cloud.es.io/api/detection_engine/rules"

api_key  = os.environ['ELASTIC_KEY']

headers = {
    "Authorization": f"ApiKey {api_key}",
    "kbn-xsrf": "true",
    "Content-Type": "application/json;charset=UTF-8"
}


def build_payload(rule: dict) -> dict | None:
    rule_type = rule.get("type")

    base = {
        "name":        rule["name"],
        "description": rule.get("description", ""),
        "enabled":     True,
        "risk_score":  rule.get("risk_score", 50),
        "severity":    rule.get("severity", "low"),
        "tags":        rule.get("tags", []),
        "threat":      rule.get("threat", []),
        "author":      rule.get("author", []),
        "type":        rule_type,
        "index":       rule.get("index", ["*"]),
        "interval":    rule.get("interval", "5m"),
        "from":        rule.get("from", "now-6m"),
        "rule_id":     rule.get("rule_id"),   # needed for PUT
    }

    if rule_type == "query":
        base.update({
            "query":    rule.get("query", ""),
            "language": rule.get("language", "kuery"),
        })

    elif rule_type == "eql":
        base.update({
            "query":    rule.get("query", ""),
            "language": "eql",
        })

    elif rule_type == "threshold":
        base.update({
            "query":     rule.get("query", ""),
            "language":  rule.get("language", "kuery"),
            "threshold": rule.get("threshold", {"field": [], "value": 1}),
        })

    else:
        print(f"  ⚠️  Unsupported rule type '{rule_type}' — skipping")
        return None

    return base
def get_existing_rule(rule_id: str):
    res = requests.get(BASE_URL, headers=headers, params={"rule_id": rule_id})
    if res.status_code == 200:
        return res.json()
    return None

def push_rule(payload: dict, filename: str):
    existing = get_existing_rule(payload["rule_id"])

    if existing:
        res = requests.put(BASE_URL, headers=headers, json=payload)
        action = "UPDATED"
    else:
        res = requests.post(BASE_URL, headers=headers, json=payload)
        action = "CREATED"

    try:
        body = res.json()
    except Exception:
        body = {"text": res.text}

    if res.status_code in (200, 201):
        print(f"  ✅ {action} [{payload['type']}] {filename} → {res.status_code}")
    else:
        print(f"  ❌ FAILED {filename} → {res.status_code}")
        print(json.dumps(body, indent=2))


# ── Main ──────────────────────────────────────────────────────────────────────
changed_files_raw = os.environ.get("CHANGED_FILES", "")
changed_files = set(changed_files_raw.split())

detection_dir = "detections"

print("CHANGED_FILES:", changed_files)

for root, dirs, files in os.walk(detection_dir):
    for file in files:
        if not file.endswith(".toml"):
            continue

        full_path = os.path.join(root, file).replace("\\", "/")

        print("Checking:", file, full_path)

        if changed_files and file not in changed_files and full_path not in changed_files:
            print("Skipping:", file)
            continue

        print(f"\nProcessing: {file}")

        with open(full_path, "rb") as f:
            alert = tomllib.load(f)

        rule = alert["rule"]
        payload = build_payload(rule)

        if payload:
            push_rule(payload, file)