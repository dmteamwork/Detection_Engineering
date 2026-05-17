import tomllib
import os
import json

# =========================
# 🔥 ATT&CK MAPPING LAYER
# =========================
# You MUST edit this based on your real detections

ATTACK_MAP = {
    # example mappings (replace with yours)
    "powershell_exec": "T1059",
    "bruteforce_login": "T1110",
    "remote_execution": "T1021",
    "c2_traffic": "T1071",
    "credential_dumping": "T1003",
    "file_discovery": "T1083",
    "process_injection": "T1055",
    "phishing": "T1566",
    "file_transfer": "T1105"
}

# Map ATT&CK technique → tactic (ATT&CK v19 compatible)
TACTIC_MAP = {
    "T1059": "execution",
    "T1110": "credential-access",
    "T1021": "lateral-movement",
    "T1071": "command-and-control",
    "T1003": "credential-access",
    "T1083": "discovery",
    "T1055": "defense-evasion",
    "T1566": "initial-access",
    "T1105": "command-and-control"
}

# =========================
# 🔍 LOAD + AGGREGATE
# =========================
techniques = {}

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if not file.endswith(".toml"):
            continue

        full_path = os.path.join(root, file)

        with open(full_path, "rb") as f:
            alert = tomllib.load(f)

        threats = alert.get("rule", {}).get("threat", [])

        for threat in threats:
            tactic = threat.get("tactic", {}).get("name", "none").lower()

            for tech in threat.get("technique", []):
                tech_id = tech.get("id")

                if not tech_id:
                    continue

                # main technique
                techniques[tech_id] = techniques.get(tech_id, {
                    "techniqueID": tech_id,
                    "tactic": tactic,
                    "score": 0
                })
                techniques[tech_id]["score"] += 1

                # subtechniques (IMPORTANT FIX)
                for sub in tech.get("subtechnique", []):
                    sub_id = sub.get("id")

                    if not sub_id:
                        continue

                    techniques[sub_id] = techniques.get(sub_id, {
                        "techniqueID": sub_id,
                        "tactic": tactic,
                        "score": 0
                    })
                    techniques[sub_id]["score"] += 1
# =========================
# 📊 BUILD NAVIGATOR JSON
# =========================
layer = {
    "name": "Custom Detections",
    "versions": {
        "attack": "19",
        "navigator": "4.8.2",
        "layer": "4.4"
    },
    "domain": "enterprise-attack",
    "description": "Auto-generated ATT&CK layer from detection-as-code pipeline",
    "filters": {
        "platforms": [
            "Linux",
            "macOS",
            "Windows",
            "Network",
            "Containers",
            "Office 365",
            "SaaS",
            "Google Workspace",
            "IaaS",
            "Azure AD"
        ]
    },
    "sorting": 0,
    "layout": {
        "layout": "side",
        "aggregateFunction": "average",
        "showID": False,
        "showName": True,
        "showAggregateScores": False,
        "countUnscored": False
    },
    "hideDisabled": False,
    "techniques": list(techniques.values()),
    "gradient": {
        "colors": [
            "#ff6666ff",
            "#ffe766ff",
            "#8ec843ff"
        ],
        "minValue": 0,
        "maxValue": 3
    },
    "legendItems": [],
    "metadata": [],
    "links": [],
    "showTacticRowBackground": False,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": True,
    "selectSubtechniquesWithParent": False
}

# =========================
# 💾 WRITE OUTPUT
# =========================
output_path = "metrics/navigator.json"
os.makedirs(os.path.dirname(output_path), exist_ok=True)

with open(output_path, "w") as f:
    json.dump(layer, f, indent=4)

print(f"[+] Navigator layer generated: {output_path}")
print(f"[+] Techniques mapped: {len(techniques)}")
