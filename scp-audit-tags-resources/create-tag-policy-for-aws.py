import json

def generar_tag_policy(servicios, tags, enforce_for):
    """
    Genera una política de etiquetas de AWS en formato JSON.

    :param servicios: Lista de servicios a los que aplicar la política.
    :param tags: Diccionario con las claves de los tags y sus valores permitidos.
    :param enforce_for: Lista de servicios donde se debe aplicar la política.
    :return: Diccionario con la política generada.
    """

    # Si enforce_for contiene "*", ignoramos la lista de servicios específicos
    #if "*" in enforce_for:
    #    enforce_for = ["*"]

    tag_policy = {"tags": {}}

    for tag_key, tag_values in tags.items():
        tag_policy["tags"][tag_key] = {
            "tag_key": {"@@assign": tag_key},
            "tag_value": {"@@assign": tag_values},
            "enforced_for": {"@@assign": enforce_for}
        }

    return tag_policy


def guardar_json(archivo, contenido, minificado=False):
    """
    Guarda un diccionario como JSON en un archivo.

    :param archivo: Nombre del archivo a guardar.
    :param contenido: Diccionario con la información JSON.
    :param minificado: Si es True, guarda en formato minificado.
    """
    with open(archivo, "w", encoding="utf-8") as f:
        if minificado:
            json.dump(contenido, f, separators=(",", ":"))  # Minificado sin espacios
        else:
            json.dump(contenido, f, indent=2, ensure_ascii=False)  # Formateado con indentación


# === CONFIGURACIÓN ===
servicios_requeridos = [""]
tags_requeridos = {
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
enforce_for = ["ec2:capacity-reservation",
                    "ec2:capacity-reservation-fleet",
                    "ec2:carrier-gateway",
                    "ec2:client-vpn-endpoint",
                    "ec2:coip-pool",
                    "ec2:customer-gateway",
                    "ec2:dedicated-host",
                    "ec2:dhcp-options",
                    "ec2:egress-only-internet-gateway",
                    "ec2:elastic-ip",
                    "ec2:export-image-task",
                    "ec2:export-instance-task",
                    "ec2:fleet",
                    "ec2:fpga-image",
                    "ec2:host-reservation",
                    "ec2:image",
                    "ec2:instance",
                    "ec2:instance-connect-endpoint",
                    "ec2:instance-event-window",
                    "ec2:internet-gateway",
                    "ec2:volume",
                    "redshift:*",
                    "redshift-serverless:namespace",
                    "redshift-serverless:workgroup"] # Si pones "*", ignorará la lista de servicios
#enforce_for = ["athena:*",
#                    "dynamodb:*",
#                    "ecr:repository",
#                    "secretsmanager:*",
#                    "elasticmapreduce:cluster",
#                    "elasticmapreduce:editor",
#                    "emr-serverless:applications",
#                    "pipes:pipe",
#                    "scheduler:schedule-group",
#                    "kms:*",
#                    "lambda:*",
#                    "sms-voice:configuration-set",
#                    "sms-voice:opt-out-list",
#                    "sms-voice:phone-number",
#                    "sms-voice:pool",
#                    "sms-voice:sender-id",
#                    "rds:cluster-endpoint",
#                    "rds:cluster-pg",
#                    "rds:db-proxy",
#                    "rds:db-proxy-endpoint",
#                    "rds:es",
#                    "rds:og",
#                    "rds:pg",
#                    "rds:ri",
#                    "rds:secgrp",
#                    "rds:subgrp",
#                    "rds:target-group",
#                    "servicecatalog:applications",
#                    "servicecatalog:attribute-groups",
#                    "catalog:portfolio",
#                    "catalog:product",
#                    "sns:topic",
#                    "states:*"]  # Si pones "*", ignorará la lista de servicios

# Generar la política
tag_policy = generar_tag_policy(servicios_requeridos, tags_requeridos, enforce_for)

# Guardar archivos JSON
guardar_json("tag_policy.json", tag_policy)          # Archivo formateado
guardar_json("tag_policy_min.json", tag_policy, minificado=True)  # Archivo minificado

print("Archivos generados: tag_policy.json (formateado) y tag_policy_min.json (minificado).")
