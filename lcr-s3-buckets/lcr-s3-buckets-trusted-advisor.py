import boto3
import logging
import os

def get_accounts_from_env():
    """Obtiene los IDs de cuentas desde una variable de ambiente."""
    account_ids = os.getenv('ACCOUNT_IDS', '')
    if not account_ids:
        logging.error("La variable de ambiente 'ACCOUNT_IDS' no está configurada o está vacía.")
        return []
    return [account.strip() for account in account_ids.split(',') if account.strip()]

def apply_lifecycle_rule(bucket_name, s3_client):
    """Aplica la regla de ciclo de vida a un bucket."""
    lifecycle_configuration = {
        'Rules': [
            {
                'ID': 'AbortIncompleteMultipartUploads',
                'Status': 'Enabled',
                'Filter': {'Prefix': ''},  # Filtro obligatorio aunque esté vacío
                'AbortIncompleteMultipartUpload': {
                    'DaysAfterInitiation': 7
                }
            }
        ]
    }
    try:
        # Aplicar la configuración de ciclo de vida
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_configuration
        )
        logging.info(f"Regla aplicada exitosamente al bucket: {bucket_name}")
    except Exception as e:
        logging.error(f"Error aplicando regla al bucket {bucket_name}: {e}", exc_info=True)

def lambda_handler(event, context):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)|  
    

    # Obtener listado de cuentas desde la variable de ambiente
    accounts = get_accounts_from_env()
    if not accounts:
        logger.error("No se encontraron cuentas para procesar. Verifique la variable de ambiente 'ACCOUNT_IDS'.")
        return

    for account_id in accounts:
        logger.info(f"Procesando cuenta: {account_id}")
        try:
            sts_client = boto3.client('sts')
            assumed_role = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole",
                RoleSessionName="ApplyLifecycleRuleSession"
            )

            s3_client = boto3.client(
                's3',
                aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_role['Credentials']['SessionToken']
            )

            buckets = s3_client.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    logger.info(f"Aplicando regla al bucket: {bucket_name}")
                    apply_lifecycle_rule(bucket_name, s3_client)
                except Exception as e:
                    logger.error(f"Error aplicando regla al bucket {bucket_name}: {e}")
        except Exception as e:
            logger.error(f"Error al asumir el rol para la cuenta {account_id}: {e}")
