import requests
import os
import tomllib

BASE_URL = "https://my-deployment-596fe6.kb.europe-west1.gcp.cloud.es.io/api/detection_engine/rules"
api_key = os.environ['ELASTIC_KEY']

headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

changed_files = os.environ.get("CHANGED_FILES", "")

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if not file.endswith(".toml"):
            continue
        if file not in changed_files:
            continue

        full_path = os.path.join(root, file)
        print(f"\nProcessing: {file}")

        with open(full_path, "rb") as toml:
            alert = tomllib.load(toml)

        rule_type = alert['rule']['type']

        if rule_type == "query":
            required_fields = ['author','description','name','rule_id','risk_score','severity','type','query','threat']
        elif rule_type == "eql":
            required_fields = ['author','description','name','rule_id','risk_score','severity','type','query','language','threat']
        elif rule_type == "threshold":
            required_fields = ['author','description','name','rule_id','risk_score','severity','type','query','threshold','threat']
        else:
            print("Unsupported rule type: " + full_path)
            continue  # use continue, not break

        data = "{\n"
        for field in alert['rule']:
            if field in required_fields:
                if type(alert['rule'][field]) == list:
                    data += "  \"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + ",\n"
                elif type(alert['rule'][field]) == str:
                    if field in ('description', 'query'):
                        data += "  \"" + field + "\": \"" + str(alert['rule'][field]).replace("\\","\\\\").replace("\"","\\\"").replace("\n"," ") + "\",\n"
                    else:
                        data += "  \"" + field + "\": \"" + str(alert['rule'][field]).replace("\"","\\\"") + "\",\n"
                elif type(alert['rule'][field]) == int:
                    data += "  \"" + field + "\": " + str(alert['rule'][field]) + ",\n"
                elif type(alert['rule'][field]) == dict:
                    data += "  \"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + ",\n"

        data += "  \"enabled\": true\n}"

        rule_id = alert['rule']['rule_id']
        # Build URL fresh each time using BASE_URL, never modify the base
        request_url = BASE_URL + "?rule_id=" + rule_id

        res = requests.put(request_url, headers=headers, data=data).json()

        if res.get("status_code") == 404:
            res = requests.post(BASE_URL, headers=headers, data=data).json()

        print(res)