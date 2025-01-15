import boto3
import logging
import os

# Configuración del logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

RULE_NAME = "AbortIncompleteMultipartUploadsLambda"
TRUSTED_ADVISOR_CHECK_ID = "c1cj39rr6v"  # Check ID correcto para "Multipart Upload Life Cycle Rule"

def get_trusted_advisor_alerts(support_client, check_id):
    """Obtiene los resultados de un check de Trusted Advisor."""
    try:
        response = support_client.describe_trusted_advisor_check_result(
            checkId=check_id,
            language='en'
        )
        return response['result']
    except Exception as e:
        logger.error(f"Error al obtener los resultados de Trusted Advisor: {e}", exc_info=True)
        return None

def get_alerted_buckets(support_client):
    """Obtiene la lista de buckets alertados por Trusted Advisor con estado 'warning'."""
    check_result = get_trusted_advisor_alerts(support_client, TRUSTED_ADVISOR_CHECK_ID)
    if not check_result:
        return []

    flagged_resources = check_result.get('flaggedResources', [])
    bucket_names = []

    for resource in flagged_resources:
        status = resource.get('status', '').lower()
        metadata = resource.get('metadata', [])
        
        # Filtrar por estado 'warning'
        if status == 'warning' and len(metadata) > 2:
            bucket_name = metadata[2]  # El nombre del bucket está en el índice 2
            bucket_names.append(bucket_name)
            logger.info(f"Bucket con estado 'warning' identificado: {bucket_name}")
        else:
            logger.debug(f"Recurso no relevante o sin metadata válida: {resource}")

    logger.info(f"Buckets alertados encontrados: {bucket_names}")
    return bucket_names

def get_all_buckets(s3_client):
    """Obtiene una lista de todos los buckets en la cuenta."""
    try:
        response = s3_client.list_buckets()
        buckets = [bucket['Name'] for bucket in response.get('Buckets', [])]
        logger.info(f"Se encontraron {len(buckets)} buckets en la cuenta.")
        return buckets
    except Exception as e:
        logger.error(f"Error al listar los buckets: {e}", exc_info=True)
        return []

def check_bucket_exists(bucket_name, s3_client):
    """Verifica si un bucket existe."""
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        logger.info(f"El bucket '{bucket_name}' existe y es accesible.")
        return True
    except s3_client.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404':
            logger.warning(f"El bucket '{bucket_name}' no existe.")
        else:
            logger.error(f"Error al verificar el bucket '{bucket_name}': {e}", exc_info=True)
        return False

def apply_lifecycle_rule(bucket_name, s3_client):
    """Aplica la regla de ciclo de vida a un bucket."""
    lifecycle_configuration = {
        'Rules': [
            {
                'ID': RULE_NAME,
                'Status': 'Enabled',
                'Filter': {'Prefix': ''},  # Filtro explícito (vacío para aplicar a todo el bucket)
                'AbortIncompleteMultipartUpload': {
                    'DaysAfterInitiation': 7
                }
            }
        ]
    }
    try:
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_configuration
        )
        logger.info(f"Regla aplicada exitosamente al bucket: {bucket_name}")
    except Exception as e:
        logger.error(f"Error al aplicar la regla al bucket {bucket_name}: {e}", exc_info=True)

def delete_lifecycle_rule(bucket_name, s3_client):
    """Elimina la regla de ciclo de vida especificada de un bucket."""
    try:
        response = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        rules = response.get('Rules', [])
        updated_rules = [rule for rule in rules if rule['ID'] != RULE_NAME]

        if len(updated_rules) < len(rules):  # Si se elimina al menos una regla
            if updated_rules:
                s3_client.put_bucket_lifecycle_configuration(
                    Bucket=bucket_name,
                    LifecycleConfiguration={'Rules': updated_rules}
                )
            else:
                s3_client.delete_bucket_lifecycle(Bucket=bucket_name)
            logger.info(f"Regla '{RULE_NAME}' eliminada del bucket: {bucket_name}")
        else:
            logger.info(f"No se encontró la regla '{RULE_NAME}' en el bucket: {bucket_name}")
    except s3_client.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchLifecycleConfiguration':
            logger.info(f"El bucket '{bucket_name}' no tiene configuración de ciclo de vida.")
        else:
            logger.error(f"Error al eliminar la regla del bucket {bucket_name}: {e}", exc_info=True)

def lambda_handler(event, context):
    """Función principal para manejar reglas de ciclo de vida en buckets."""
    # Leer variable para eliminar reglas
    delete_rule = os.getenv('DELETE_RULE', 'false').lower() == 'true'

    # Crear clientes de AWS
    s3_client = boto3.client('s3')
    support_client = boto3.client('support')

    if delete_rule:
        logger.info("Modo eliminación activado. Eliminando reglas de ciclo de vida de todos los buckets.")
        all_buckets = get_all_buckets(s3_client)
        for bucket_name in all_buckets:
            if check_bucket_exists(bucket_name, s3_client):
                delete_lifecycle_rule(bucket_name, s3_client)
            else:
                logger.warning(f"El bucket '{bucket_name}' no existe o no es accesible.")
    else:
        logger.info("Aplicando reglas de ciclo de vida a los buckets alertados por Trusted Advisor.")
        alerted_buckets = get_alerted_buckets(support_client)
        for bucket_name in alerted_buckets:
            if check_bucket_exists(bucket_name, s3_client):
                apply_lifecycle_rule(bucket_name, s3_client)
            else:
                logger.warning(f"El bucket '{bucket_name}' no existe o no es accesible.")
