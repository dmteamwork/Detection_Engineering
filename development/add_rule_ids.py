import os
import uuid
import tomllib
import tomli_w #pip install tomli-w

detection_dir = "/home/kali/Desktop/AttackS/vs_code_toml_elastic/detection_engineering"

for root, dirs, files in os.walk(detection_dir):
    for file in files:
        if not file.endswith(".toml"):
            continue

        full_path = os.path.join(root, file)

        with open(full_path, "rb") as f:
            data = tomllib.load(f)

        if "rule_id" not in data.get("rule", {}):
            data["rule"]["rule_id"] = str(uuid.uuid4())

            with open(full_path, "wb") as f:
                tomli_w.dump(data, f)

            print(f"  Added rule_id to {file}: {data['rule']['rule_id']}")
        else:
            print(f"    Skipped {file} — rule_id already exists")