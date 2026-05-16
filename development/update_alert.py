import requests
import os
import tomllib
import json

BASE_URL = "https://my-deployment-596fe6.kb.europe-west1.gcp.cloud.es.io"
api_key = "NHF5UkNwNEJTX3RNbGFPTFc1dEs6aDdmMnpmNUFzNXZWMUlUWEEzdG1jUQ=="

headers = {
    "Authorization": f"ApiKey {api_key}",
    "kbn-xsrf": "true",
    "Content-Type": "application/json;charset=UTF-8"
}

RULES_URL = f"{BASE_URL}/api/detection_engine/rules"

# ✅ Get changed files from GitHub Actions
changed_files = os.environ.get("CHANGED_FILES", "")
print("CHANGED_FILES:", changed_files)


def build_payload(rule: dict) -> dict | None:
    rule_type = rule.get("type")

    raw_index = rule.get("index", {})

# Handle [rule.index] with nested "indices" key
    if isinstance(raw_index, dict):
        raw_index = raw_index.get("indices", [])

# Handle plain string
    if isinstance(raw_index, str):
        raw_index = [raw_index]

# Final fallback
    if not raw_index:
        raw_index = ["logs-*", "winlogbeat-*", "filebeat-*", "endgame-*"]


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
        "index": rule.get("indices", ["logs-*", "winlogbeat-*", "filebeat-*"]),
        "interval":    rule.get("interval", "5m"),
        "from":        rule.get("from", "now-6m"),
        "rule_id":     rule.get("rule_id"),
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


def push_rule(payload: dict, filename: str):
    rule_id = payload.get("rule_id")

    if not rule_id:
        print(f"  ❌ No rule_id found in {filename} — skipping")
        return

    # ✅ FIXED: pass rule_id as query param
    put_url = f"{RULES_URL}?rule_id={rule_id}"
    put_res = requests.put(put_url, headers=headers, json=payload)

    if put_res.status_code == 404:
        post_res = requests.post(RULES_URL, headers=headers, json=payload)
        status = post_res.status_code
        body   = post_res.json()
        action = "CREATED"
    else:
        status = put_res.status_code
        body   = put_res.json()
        action = "UPDATED"

    if status in (200, 201):
        print(f"  ✅ {action} [{payload['type']}] {filename} → {status}")
    else:
        print(f"  ❌ FAILED {filename} → {status}")
        print(f"     {json.dumps(body, indent=2)}")


# ── Main ──────────────────────────────────────────────────────────────────────
detection_dir = "detections/"

for root, dirs, files in os.walk(detection_dir):
    for file in files:
        if not file.endswith(".toml"):
            continue

        full_path = os.path.join(root, file)

        # ✅ Skip files that were not changed
        if file not in changed_files and full_path not in changed_files:
            continue

        print(f"\nProcessing: {file}")

        with open(full_path, "rb") as f:
            alert = tomllib.load(f)

        rule    = alert["rule"]
        payload = build_payload(rule)

        if payload:
            push_rule(payload, file)