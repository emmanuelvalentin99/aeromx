import json
import re

def sanitize_sid(sid):
    return re.sub(r'[^a-zA-Z0-9]', '', sid)

def generate_scp(actions, resources, tags, tag_type="RequestTag"):
    statements = []
    
    for tag, valid_values in tags.items():
        sanitized_sid_tag = sanitize_sid(tag)  # Eliminar guiones y caracteres especiales solo en el Sid
        
        statements.append({
            "Sid": f"DenyWithoutTag{sanitized_sid_tag}",
            "Effect": "Deny",
            "Action": actions,
            "Resource": resources,
            "Condition": {
                "Null": {
                    f"aws:{tag_type}/{tag}": "true"
                }
            }
        })
        
        statements.append({
            "Sid": f"DenyWithoutValid{sanitized_sid_tag}Tag",
            "Effect": "Deny",
            "Action": actions,
            "Resource": resources,
            "Condition": {
                "StringNotEqualsIfExists": {
                    f"aws:{tag_type}/{tag}": valid_values
                }
            }
        })
    
    policy = {
        "Version": "2012-10-17",
        "Statement": statements
    }
    
    policy_json_pretty = json.dumps(policy, indent=4)
    policy_json_compact = json.dumps(policy, separators=(",", ":"))
    
    return policy_json_pretty, policy_json_compact

# Ejemplo de uso
actions = [
    "lambda:CreateFunction",
    "lambda:CreateAlias",
    "sns:CreateTopic",
    "appflow:CreateFlow"
]
resources = [
    "arn:aws:appflow:*:*:flow/*",
    "arn:aws:lambda:*:*:function:*",
    "arn:aws:sns:*:*:*"
    ]
tags = {
    "Area": ["Cargo","Mantenimiento","Operaciones","Aeropuertos","Seguridad-aerea","Revenie-accounting","Call-center","DataAnalytics","Estrategia-de-ingresos","Pricing","Svoc","Voc","Revenue-management","Marketing"],
    "Environment": ["dev","qa","prod"],
    "Vertical": ["comm","cust","corp","cha-beth","svoe","oper","ia","de"],
    "map-migrated": ["d-server-03cd3bbblu0msp"],
    "Ambiente": ["PD","Q","DE"],
    "AreaResponsable": ["DA-AI"]
}

tag_type = "RequestTag"  # Cambia a "ResourceTag" si lo necesitas

policy_json_pretty, policy_json_compact = generate_scp(actions, resources, tags, tag_type)

# Guardar en archivos JSON
with open("scp_policy.json", "w") as f:
    f.write(policy_json_pretty)

with open("scp_policy_minified.json", "w") as f:
    f.write(policy_json_compact)

print(policy_json_pretty)
print("Minified policy saved to scp_policy_minified.json")
