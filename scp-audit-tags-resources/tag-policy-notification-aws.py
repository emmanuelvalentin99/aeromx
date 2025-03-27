import json
import boto3
import sys

# ✅ Configuración para ajustar servicios, regiones y tags esperados
config_data = {
    "AWS_ACCOUNTS": ["939791606331"],  # Agrega más cuentas si es necesario
    "ROLE_NAME": "am-tag-policy-notification-role",
    "REGIONS_TO_CHECK": [
        "us-east-1"
    ]
}


def get_assumed_role_credentials(account_id, role_name):
    """Asumir el rol en la cuenta objetivo."""
    sts_client = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="LambdaSession"
        )
        credentials = response['Credentials']
        print(f"✅ Rol asumido correctamente en la cuenta {account_id}")
        return credentials
    except Exception as e:
        print(f"❗️ Error al asumir rol en la cuenta {account_id}: {str(e)}")
        raise Exception(f"Error crítico: No se pudo asumir el rol en la cuenta {account_id}. Verifica permisos.")


def get_client(service, credentials, region=None):
    """Inicializar cliente para el servicio."""
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )


### 🎯 Función para comparar etiquetas esperadas ###
def compare_tags(expected_tags, resource_tags):
    """Validar si las etiquetas de un recurso cumplen con las etiquetas esperadas."""
    
    # Crear diccionario de etiquetas del recurso para comparación rápida
    resource_tag_dict = {tag['Key']: tag['Value'] for tag in resource_tags}
    
    # Verificar si todas las etiquetas requeridas existen y tienen valores válidos
    for key, expected_values in expected_tags.items():
        # 🚨 Verificar si la etiqueta está ausente o si el valor no es válido
        if key not in resource_tag_dict or resource_tag_dict[key] not in expected_values:
            return False  # ❌ Error, salir inmediatamente
    
    return True  # ✅ Todas las etiquetas son correctas


### 🎯 Función para validar etiquetas y clasificar recursos ###
def validate_and_classify(resource_type, resource_name, resource_tags, expected_tags):
    """Evaluar etiquetas y clasificar el recurso."""
    if not resource_tags:
        yield {
            'resource_type': resource_type,
            'resource_name': resource_name,
            'status': 'MISSING_TAGS',
            'tags': []
        }
    
    elif not compare_tags(expected_tags, resource_tags):
        yield {
            'resource_type': resource_type,
            'resource_name': resource_name,
            'status': 'INVALID_TAGS',
            'tags': resource_tags
        }


### 🎯 Funciones para obtener recursos y validar etiquetas ###

def list_s3_buckets(credentials, expected_tags):
    """Listar buckets S3 y validar etiquetas."""
    s3_client = get_client('s3', credentials)
    
    response = s3_client.list_buckets()
    for bucket in response['Buckets']:
        bucket_name = bucket['Name']
        try:
            tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
            tags = tags_response['TagSet']
        except Exception:
            tags = []
        
        yield from validate_and_classify('s3', bucket_name, tags, expected_tags)


def list_ec2_instances(credentials, region, expected_tags):
    """Listar instancias EC2 y validar etiquetas."""
    ec2_client = get_client('ec2', credentials, region)
    
    response = ec2_client.describe_instances()
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            tags = instance.get('Tags', [])
            
            yield from validate_and_classify('ec2', instance_id, tags, expected_tags)


def list_lambda_functions(credentials, region, expected_tags):
    """Listar funciones Lambda y validar etiquetas."""
    lambda_client = get_client('lambda', credentials, region)
    
    response = lambda_client.list_functions()
    for function in response['Functions']:
        function_arn = function['FunctionArn']
        try:
            tags_response = lambda_client.list_tags(Resource=function_arn)
            tags = [{'Key': k, 'Value': v} for k, v in tags_response.get('Tags', {}).items()]
        except Exception:
            tags = []
        
        yield from validate_and_classify('lambda', function['FunctionName'], tags, expected_tags)


def list_rds_instances(credentials, region, expected_tags):
    """Listar instancias RDS y validar etiquetas."""
    rds_client = get_client('rds', credentials, region)
    
    response = rds_client.describe_db_instances()
    for instance in response['DBInstances']:
        instance_arn = instance['DBInstanceArn']
        try:
            tags_response = rds_client.list_tags_for_resource(ResourceName=instance_arn)
            tags = tags_response.get('TagList', [])
        except Exception:
            tags = []
        
        yield from validate_and_classify('rds', instance['DBInstanceIdentifier'], tags, expected_tags)


def list_sns_topics(credentials, region, expected_tags):
    """Listar tópicos SNS y validar etiquetas."""
    sns_client = get_client('sns', credentials, region)
    
    response = sns_client.list_topics()
    for topic in response['Topics']:
        topic_arn = topic['TopicArn']
        try:
            tags_response = sns_client.list_tags_for_resource(ResourceArn=topic_arn)
            tags = tags_response.get('Tags', [])
        except Exception:
            tags = []
        
        yield from validate_and_classify('sns', topic_arn, tags, expected_tags)


### 🎯 Función Principal ###

def lambda_handler(event, context):
    aws_accounts = config_data['AWS_ACCOUNTS']
    role_name = config_data['ROLE_NAME']
    regions_to_check = config_data['REGIONS_TO_CHECK']
    expected_tags = config_data['EXPECTED_TAGS']

    # ✅ Listas para resultados finales
    resources_without_tags = []
    resources_with_invalid_tags = []
    
    for account_id in aws_accounts:
        try:
            # ⚡️ Asumir el rol para la cuenta
            credentials = get_assumed_role_credentials(account_id, role_name)
            
            # ✅ Obtener y validar etiquetas para S3
            for result in list_s3_buckets(credentials, expected_tags):
                if result['status'] == 'MISSING_TAGS':
                    resources_without_tags.append(result)
                elif result['status'] == 'INVALID_TAGS':
                    resources_with_invalid_tags.append(result)
            
            for region in regions_to_check:
                # ✅ Validar etiquetas para otros servicios
                for result in list_ec2_instances(credentials, region, expected_tags):
                    if result['status'] == 'MISSING_TAGS':
                        resources_without_tags.append(result)
                    elif result['status'] == 'INVALID_TAGS':
                        resources_with_invalid_tags.append(result)

                for result in list_lambda_functions(credentials, region, expected_tags):
                    if result['status'] == 'MISSING_TAGS':
                        resources_without_tags.append(result)
                    elif result['status'] == 'INVALID_TAGS':
                        resources_with_invalid_tags.append(result)

                for result in list_rds_instances(credentials, region, expected_tags):
                    if result['status'] == 'MISSING_TAGS':
                        resources_without_tags.append(result)
                    elif result['status'] == 'INVALID_TAGS':
                        resources_with_invalid_tags.append(result)

                for result in list_sns_topics(credentials, region, expected_tags):
                    if result['status'] == 'MISSING_TAGS':
                        resources_without_tags.append(result)
                    elif result['status'] == 'INVALID_TAGS':
                        resources_with_invalid_tags.append(result)
        
        except Exception as e:
            print(f"❗️ Error crítico en la cuenta {account_id}: {str(e)}")
            return {
                'statusCode': 500,
                'body': json.dumps({'error': str(e)})
            }

    # 📚 Depuración para verificar cuántos recursos fueron encontrados
    print(f"✅ Recursos SIN etiquetas: {len(resources_without_tags)}")
    print(f"⚠️ Recursos con etiquetas inválidas: {len(resources_with_invalid_tags)}")

    # 🎯 Resumen Final
    return {
        'statusCode': 200,
        'body': json.dumps({
            'resources_without_tags': resources_without_tags[:100],  # Limitar resultados
            'resources_with_invalid_tags': resources_with_invalid_tags[:100]  # Limitar resultados
        }, indent=2)
    }
