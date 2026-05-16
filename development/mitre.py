import requests
import tomllib
import os
import sys

# =========================
#  LOAD MITRE DATA
# =========================
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
mitreData = requests.get(url).json()

mitreMapped = {}
failure = 0

for obj in mitreData["objects"]:
    if obj.get("type") != "attack-pattern":
        continue

    if obj.get("external_references"):
        for ref in obj["external_references"]:
            ext_id = ref.get("external_id")

            if not ext_id or not ext_id.startswith("T"):
                continue

            tactics = []

            for phase in obj.get("kill_chain_phases", []):
                tactics.append(phase.get("phase_name"))

            mitreMapped[ext_id] = {
                "tactics": tactics,
                "name": obj.get("name"),
                "url": ref.get("url"),
                "deprecated": obj.get("x_mitre_deprecated", False)
            }

# =========================
#  LOAD DETECTIONS
# =========================
alert_data = {}

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if not file.endswith(".toml"):
            continue

        full_path = os.path.join(root, file)

        with open(full_path, "rb") as f:
            alert = tomllib.load(f)

        threats = alert.get("rule", {}).get("threat", [])

        filtered_object_array = []

        for threat in threats:
            tech = threat.get("technique", [{}])[0]

            technique_id = tech.get("id")
            technique_name = tech.get("name")

            tactic = threat.get("tactic", {}).get("name", "none")

            sub = tech.get("subtechnique", [{}])
            if sub and isinstance(sub, list) and "id" in sub[0]:
                subtechnique_id = sub[0]["id"]
                subtechnique_name = sub[0].get("name", "none")
            else:
                subtechnique_id = "none"
                subtechnique_name = "none"

            filtered_object_array.append({
                "tactic": tactic,
                "technique_id": technique_id,
                "technique_name": technique_name,
                "subtechnique_id": subtechnique_id,
                "subtechnique_name": subtechnique_name
            })

        alert_data[file] = filtered_object_array

# =========================
#  VALIDATION
# =========================
mitre_tactic_list = [
    "reconnaissance", "resource development", "initial access",
    "execution", "persistence", "privilege escalation",
    "defense evasion", "credential access", "discovery",
    "lateral movement", "collection", "command and control",
    "exfiltration", "impact", "none"
]

for file, lines in alert_data.items():
    for line in lines:

        tactic = line["tactic"].lower()
        technique_id = line["technique_id"]
        subtechnique_id = line["subtechnique_id"]

        # Validate tactic
        if tactic not in mitre_tactic_list:
            print(f"[!] Invalid tactic '{tactic}' in {file}")
            failure = 1

        # Validate technique existence
        if technique_id not in mitreMapped:
            print(f"[!] Invalid MITRE Technique ID '{technique_id}' in {file}")
            failure = 1
            continue

        mitre_name = mitreMapped[technique_id]["name"]
        alert_name = line["technique_name"]

        if alert_name != mitre_name:
            print(f"[!] Name mismatch in {file}")
            print(f"    EXPECTED: {mitre_name}")
            print(f"    GIVEN:    {alert_name}")
            failure = 1

        # Validate subtechnique
        if subtechnique_id != "none":
            if subtechnique_id not in mitreMapped:
                print(f"[!] Invalid subtechnique ID '{subtechnique_id}' in {file}")
                failure = 1
                continue

            mitre_sub_name = mitreMapped[subtechnique_id]["name"]
            if subtechnique_id not in mitreMapped:
                print("Invalid subtechnique ID")

        # Check deprecated
        if mitreMapped[technique_id].get("deprecated"):
            print(f"[!] Deprecated technique {technique_id} in {file}")
            failure = 1

# =========================
# EXIT STATUS
# =========================
if failure:
    sys.exit(1)