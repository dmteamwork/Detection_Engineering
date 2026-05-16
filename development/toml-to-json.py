import requests
import os
import tomllib
import json

url = "https://my-deployment-596fe6.kb.europe-west1.gcp.cloud.es.io/api/detection_engine/rules"

api_key = os.environ.get("ELASTIC_KEY")

headers = {
    "Authorization": f"ApiKey {api_key}",
    "kbn-xsrf": "true",
    "Content-Type": "application/json"
}

for root, dirs, files in os.walk("detections/"):
    for file in files:

        if not file.endswith(".toml"):
            continue

        full_path = os.path.join(root, file)

        with open(full_path, "rb") as f:
            alert = tomllib.load(f)

        rule = alert.get("rule", {})
        rule_type = rule.get("type")

        if rule_type == "query":
            required_fields = ['author','description','name','rule_id','risk_score','severity','type','query','threat']

        elif rule_type == "eql":
            required_fields = ['author','description','name','rule_id','risk_score','severity','type','query','language','threat']

        elif rule_type == "threshold":
            required_fields = ['author','description','name','rule_id','risk_score','severity','type','query','threshold','threat']

        else:
            print(f"[!] Unsupported rule type in {file}")
            continue

        payload = {}

        for field in required_fields:
            if field in rule:
                payload[field] = rule[field]

        payload["enabled"] = True

        try:
            response = requests.post(url, headers=headers, json=payload)

            print(file, response.status_code, response.text)

        except Exception as e:
            print(f"[!] Error sending {file}: {e}")