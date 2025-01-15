import boto3
import logging
import os

# Configuración del logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

RULE_NAME = 'createdFromLambdaAIMU'  # Nombre de la regla que debe coincidir
TRUSTED_ADVISOR_CHECK_ID = "c1cj39rr6v"  # ID del check de Trusted Advisor para "Multipart Upload Life Cycle Rule"

def get_accounts_from_env():
    """Obtiene los IDs de cuentas desde una variable de ambiente."""
    account_ids = os.getenv('ACCOUNT_IDS', '')
    if not account_ids:
        logger.error("La variable de ambiente 'ACCOUNT_IDS' no está configurada o está vacía.")
        return []
    return [account.strip() for account in account_ids.split(',') if account.strip()]

def get_alerted_buckets(support_client):
    """Obtiene los buckets alertados por Trusted Advisor con estado 'warning'."""
    try:
        response = support_client.describe_trusted_advisor_check_result(
            checkId=TRUSTED_ADVISOR_CHECK_ID,
            language='en'
        )
        flagged_resources = response.get('result', {}).get('flaggedResources', [])
        bucket_names = []

        for resource in flagged_resources:
            status = resource.get('status', '').lower()
            metadata = resource.get('metadata', [])
            
            # Filtrar por estado 'warning'
            if status == 'warning' and len(metadata) > 2:
                bucket_name = metadata[2]  # El nombre del bucket está en el índice 2
                bucket_names.append(bucket_name)
                logger.info(f"Bucket alertado con estado 'warning': {bucket_name}")
        
        return bucket_names

    except Exception as e:
        logger.error(f"Error al obtener los resultados de Trusted Advisor: {e}", exc_info=True)
        return []

def apply_lifecycle_rule(bucket_name, s3_client):
    """Aplica la regla de ciclo de vida a un bucket."""
    lifecycle_configuration = {
        'Rules': [
            {
                'ID': RULE_NAME,
                'Status': 'Enabled',
                'Filter': {'Prefix': ''},  # Filtro explícito para aplicar a todo el bucket
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
        logger.error(f"Error aplicando regla al bucket {bucket_name}: {e}", exc_info=True)

def delete_lifecycle_rule(bucket_name, s3_client):
    """Elimina la regla de ciclo de vida especificada de un bucket."""
    try:
        response = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        rules = response.get('Rules', [])
        updated_rules = [rule for rule in rules if rule['ID'] != RULE_NAME]

        if len(updated_rules) < len(rules):  # Si hay reglas eliminadas
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

def assume_role(account_id):
    """Asume un rol en una cuenta especificada y devuelve las credenciales."""
    try:
        sts_client = boto3.client('sts')
        assumed_role = sts_client.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole",
            RoleSessionName="LifecycleRuleSession"
        )
        credentials = assumed_role['Credentials']
        logger.info(f"Rol asumido exitosamente en la cuenta {account_id}")
        return credentials
    except Exception as e:
        logger.error(f"Error al asumir el rol en la cuenta {account_id}: {e}", exc_info=True)
        return None

def process_buckets_in_account(account_id, delete_rule, s3_client):
    """Procesa los buckets alertados en una cuenta (aplicando o eliminando reglas de ciclo de vida)."""
    if delete_rule:
        # Si es modo eliminación, escanear todos los buckets
        logger.info(f"Eliminando reglas '{RULE_NAME}' en todos los buckets de la cuenta {account_id}")
        buckets = s3_client.list_buckets().get('Buckets', [])
        for bucket in buckets:
            bucket_name = bucket['Name']
            logger.info(f"Eliminando regla '{RULE_NAME}' del bucket: {bucket_name}")
            delete_lifecycle_rule(bucket_name, s3_client)
    else:
        # Si no es modo eliminación, solo procesar los buckets alertados
        alerted_buckets = get_alerted_buckets(boto3.client('support'))

        if not alerted_buckets:
            logger.info(f"No hay buckets alertados en Trusted Advisor para la cuenta {account_id}.")
            return

        for bucket_name in alerted_buckets:
            logger.info(f"Aplicando regla '{RULE_NAME}' al bucket: {bucket_name}")
            apply_lifecycle_rule(bucket_name, s3_client)

def lambda_handler(event, context):
    """Manejador principal de Lambda."""
    delete_rule = os.getenv('DELETE_RULE', 'false').lower() == 'true'
    accounts = get_accounts_from_env()

    if not accounts:
        logger.error("No se encontraron cuentas para procesar. Verifique la variable de ambiente 'ACCOUNT_IDS'.")
        return

    for account_id in accounts:
        logger.info(f"Procesando cuenta: {account_id}")
        credentials = assume_role(account_id)
        if not credentials:
            continue

        s3_client = boto3.client(
            's3',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )

        process_buckets_in_account(account_id, delete_rule, s3_client)
