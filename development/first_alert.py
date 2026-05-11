
# """"Try the empty actions approach first to confirm the rest of the payload works correctly."""
# import requests
# import json

# url = "https://my-deployment-596fe6.kb.europe-west1.gcp.cloud.es.io/api/alerting/rule/"
# api_key = "NHF5UkNwNEJTX3RNbGFPTFc1dEs6aDdmMnpmNUFzNXZWMUlUWEEzdG1jUQ=="

# headers = {
#     "Authorization": f"ApiKey {api_key}",
#     "kbn-xsrf": "true",
#     "Content-Type": "application/json;charset=UTF-8"
# }

# payload = {
#     "params": {
#         "aggType": "avg",
#         "termSize": 6,
#         "thresholdComparator": ">",
#         "timeWindowSize": 5,
#         "timeWindowUnit": "m",
#         "groupBy": "top",
#         "threshold": [1000],
#         "index": [".test-index"],
#         "timeField": "@timestamp",
#         "aggField": "sheet.version",
#         "termField": "name.keyword"
#     },
#     "consumer": "alerts",
#     "rule_type_id": ".index-threshold",
#     "schedule": {
#         "interval": "1m"
#     },
#     "actions": [],          # empty — no connector needed
#     "tags": ["cpu"],
#     "notify_when": "onActionGroupChange",
#     "name": "my alert"
# }

# response = requests.post(url, headers=headers, json=payload)

# print(f"Status Code: {response.status_code}")
# print(f"Response: {json.dumps(response.json(), indent=2)}")




"""working but all as threshold"""
# import requests
# import os
# import tomllib
# import json

# url = "https://my-deployment-596fe6.kb.europe-west1.gcp.cloud.es.io/api/alerting/rule"
# api_key = "NHF5UkNwNEJTX3RNbGFPTFc1dEs6aDdmMnpmNUFzNXZWMUlUWEEzdG1jUQ=="

# headers = {
#     "Authorization": f"ApiKey {api_key}",
#     "kbn-xsrf": "true",
#     "Content-Type": "application/json;charset=UTF-8"
# }

# for root, dirs, files in os.walk("/home/kali/Desktop/AttackS/toml/converted_detection"):
#     for file in files:
#         if file.endswith(".toml"):
#             full_path = os.path.join(root, file)
#             with open(full_path, "rb") as f:
#                 alert = tomllib.load(f)

#             rule = alert["rule"]
#             payload = {
#                 "name":        rule["name"],
#                 "consumer":    "alerts",
#                 "rule_type_id": ".index-threshold",
#                 "schedule":    {"interval": "1m"},
#                 "actions":     [],
#                 "tags":        rule.get("tags", []),
#                 "params": {
#                     "index":     [".test-index"],
#                     "timeField": "@timestamp",
#                     "aggType":   "count",
#                     "threshold": [rule.get("risk_score", 50)],
#                     "thresholdComparator": ">",
#                     "timeWindowSize": 5,
#                     "timeWindowUnit": "m",
#                     "groupBy":   "all"
#                 }
#             }

#             # Try UPDATE first, then CREATE if not found
#             put_response = requests.put(
#                 f"{url}", headers=headers, json=payload
#             )

#             if put_response.status_code == 404:
#                 post_response = requests.post(url, headers=headers, json=payload)
#                 print(f"CREATED {file}: {post_response.status_code}")
#             else:
#                 print(f"UPDATED {file}: {put_response.status_code}")


import requests
import os
import tomllib
import json

BASE_URL = "https://my-deployment-596fe6.kb.europe-west1.gcp.cloud.es.io"
api_key  = os.environ['ELASTIC_KEY']

headers = {
    "Authorization": f"ApiKey {api_key}",
    "kbn-xsrf": "true",
    "Content-Type": "application/json;charset=UTF-8"
}

RULES_URL = f"{BASE_URL}/api/detection_engine/rules"


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
        "index": rule.get("index", {}).get("indices", ["*"]),
        "interval":    rule.get("interval", "5m"),
        "from":        rule.get("from", "now-6m"),
        "alert_suppression": rule.get("alert_suppression", {}),
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
    post_res = requests.post(RULES_URL, headers=headers, json=payload)
    status   = post_res.status_code
    body     = post_res.json()

    if status in (200, 201):
        print(f"  ✅ CREATED [{payload['type']}] {filename} → {status}")
    else:
        print(f"  ❌ FAILED {filename} → {status}")
        print(f"     {json.dumps(body, indent=2)}")


# ── Main ──────────────────────────────────────────────────────────────────────
detection_dir = "/home/kali/Desktop/AttackS/vs_code_toml_elastic/detection_engineering/detections"

for root, dirs, files in os.walk(detection_dir):
    for file in files:
        if not file.endswith(".toml"):
            continue

        full_path = os.path.join(root, file)
        print(f"\nProcessing: {file}")

        with open(full_path, "rb") as f:
            alert = tomllib.load(f)

        rule    = alert["rule"]
        payload = build_payload(rule)

        if payload:
            push_rule(payload, file)