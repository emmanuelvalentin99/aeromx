import json

def generate_scp(actions, resources, tags, tag_type="RequestTag"):
    statements = []
    
    for tag, valid_values in tags.items():
        statements.append({
            "Sid": f"DenyWithoutTag{tag}",
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
            "Sid": f"DenyWithoutValid{tag}Tag",
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
    
    policy_json = json.dumps(policy, indent=4)
    policy_json = policy_json.replace("}\n        ]", "},\n        ]")  # Agrega una coma al final de cada statement excepto el último
    return policy_json

# Ejemplo de uso
actions = ["airflow:CreateEnvironment"]
resources = ["arn:aws:airflow:*:*:environment/*"]
tags = {
    "Area": ["Cargo","Mantenimiento","Operaciones","Aeropuertos","Seguridad-aerea","Revenie-accounting","Call-center","DataAnalytics","Estrategia-de-ingresos","Pricing","Svoc","Voc","Revenue-management","Marketing"],
    "Environment": ["dev","qa","prod"],
    "Vertical": ["comm","cust","corp","cha-beth","svoe","oper","ia","de"],
    "map-migrated": ["d-server-03cd3bbblu0msp"],
    "Ambiente": ["PD","Q","DE"],
    "AreaResponsable": ["DA-AI"],
    "CentroDeCosto": ["121001"],
    "DuenoDeLaCuenta": ["amsoportedatalake@aeromexico.com"],
    "Proyecto": ["Datalake"],
    "Aplicacion": ["Datalake"],
    "ImpactoANegocio": ["Tier1","Tier2","Tier3","Tier4"],
    "lcf": ["IF","DP","NA"]
}

tag_type = "RequestTag"  # Cambia a "ResourceTag" si lo necesitas

policy_json = generate_scp(actions, resources, tags, tag_type)

# Guardar en un archivo JSON
with open("scp_policy.json", "w") as f:
    f.write(policy_json)

print(policy_json)
