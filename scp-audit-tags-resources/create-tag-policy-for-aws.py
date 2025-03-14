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
    if "*" in enforce_for:
        enforce_for = ["*"]

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
servicios_requeridos = ["*"]
tags_requeridos = {
    "Area": ["Cargo","Mantenimiento","Operaciones","Aeropuertos","Seguridad-aerea","Revenie-accounting","Call-center","DataAnalytics","Estrategia-de-ingresos","Pricing","Svoc","Voc","Revenue-management","Marketing"],
    "Environment": ["dev","qa","prod"],
    "Vertical": ["comm","cust","corp","cha-beth","svoe","oper","ia","de"],
    "ProjectName": {*}
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
enforce_for = ["*"]  # Si pones "*", ignorará la lista de servicios

# Generar la política
tag_policy = generar_tag_policy(servicios_requeridos, tags_requeridos, enforce_for)

# Guardar archivos JSON
guardar_json("tag_policy.json", tag_policy)          # Archivo formateado
guardar_json("tag_policy_min.json", tag_policy, minificado=True)  # Archivo minificado

print("Archivos generados: tag_policy.json (formateado) y tag_policy_min.json (minificado).")
