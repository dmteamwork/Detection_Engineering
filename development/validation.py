import tomllib
import sys
import os

failure = 0

REQUIRED_BY_TYPE = {
    "query":     ['description', 'name', 'risk_score', 'severity', 'type', 'query'],
    "eql":       ['description', 'name', 'risk_score', 'severity', 'type', 'query'],
    "threshold": ['description', 'name', 'risk_score', 'severity', 'type', 'query', 'threshold'],
}

for root, dirs, files in os.walk("/home/kali/Desktop/AttackS/toml/converted_detection"):
    for file in files:
        if not file.endswith(".toml"):
            continue

        full_path = os.path.join(root, file)
        with open(full_path, "rb") as f:
            alert = tomllib.load(f)

        rule = alert.get('rule', {})
        rule_type = rule.get('type')

        if rule_type not in REQUIRED_BY_TYPE:
            print(f"Unsupported rule type '{rule_type}' in: {file}")
            failure = 1
            continue

        # Check directly against rule's keys — no fragile nested iteration
        present_fields = set(rule.keys())
        required_fields = REQUIRED_BY_TYPE[rule_type]
        missing_fields = [f for f in required_fields if f not in present_fields]

        if missing_fields:
            print(f"Missing fields in {file}: {missing_fields}")
            failure = 1
        else:
            print(f"Validation passed: {file}")

if failure != 0:
    sys.exit(1)