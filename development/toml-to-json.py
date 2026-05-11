import requests
import os
import tomllib

url = "https://detectionengineering101.kb.us-central1.gcp.cloud.es.io/api/detection_engine/rules"
api_key = os.environ['ELASTIC_KEY']
headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

data = ""

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml_file:
                alert = tomllib.load(toml_file)

            # Get the rule part
            rule_data = alert.get('rule', {})
            
            # Create a clean dictionary with ONLY the fields Elastic wants
            payload = {
                "name": rule_data.get("name"),
                "description": rule_data.get("description"),
                "risk_score": rule_data.get("risk_score"),
                "severity": rule_data.get("severity"),
                "type": rule_data.get("type"),
                "query": rule_data.get("query"),
                "threat": rule_data.get("threat"),
                "author": rule_data.get("author"),
                "enabled": True
            }

            # If it's EQL, add the language field
            if rule_data.get("type") == "eql":
                payload["language"] = "eql"

            # Send the request using the 'json' parameter (automatically handles headers)
            response = requests.post(url, headers=headers, json=payload)
            print(f"File: {file} | Status: {response.status_code} | Response: {response.json()}")