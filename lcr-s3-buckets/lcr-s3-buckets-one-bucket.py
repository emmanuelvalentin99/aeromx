import boto3
import logging

# Configuración del logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

def apply_lifecycle_rule(bucket_name, s3_client):
    """Aplica la regla de ciclo de vida a un bucket."""
    lifecycle_configuration = {
        'Rules': [
            {
                'ID': 'AbortIncompleteMultipartUploads',
                'Status': 'Enabled',
                'Filter': {'Prefix': ''},  # Filtro explícito (vacío para aplicar a todo el bucket)
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
        logger.info(f"Regla aplicada exitosamente al bucket: {bucket_name}")
    except Exception as e:
        logger.error(f"Error al aplicar la regla al bucket {bucket_name}: {e}", exc_info=True)

def check_bucket_exists(bucket_name, s3_client):
    """Verifica si un bucket existe."""
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        return True
    except s3_client.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404':
            logger.warning(f"El bucket '{bucket_name}' no existe.")
        else:
            logger.error(f"Error al verificar el bucket '{bucket_name}': {e}", exc_info=True)
        return False

def lambda_handler(event, context):
    """Función principal para aplicar reglas de ciclo de vida a un bucket específico."""
    # Obtener el nombre del bucket desde el evento o configurarlo manualmente
    bucket_name = event.get('bucket_name', None)

    if not bucket_name:
        logger.error("No se especificó un bucket_name en el evento.")
        return

    # Crear cliente de S3
    s3_client = boto3.client('s3')

    # Verificar si el bucket existe antes de aplicar la regla
    if check_bucket_exists(bucket_name, s3_client):
        logger.info(f"El bucket '{bucket_name}' existe. Aplicando regla...")
        apply_lifecycle_rule(bucket_name, s3_client)
    else:
        logger.info(f"No se aplicaron reglas al bucket '{bucket_name}' ya que no existe.")

# Para ejecutar localmente
if __name__ == "__main__":
    # Simulación de evento con el nombre del bucket
    test_event = {
        "bucket_name": "nombre-del-bucket-a-verificar"
    }
    lambda_handler(test_event, None)
