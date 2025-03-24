import json
import boto3
import sys

# ✅ Configuración embebida para ajustar servicios, regiones y tags
config_data = {
    "AWS_ACCOUNTS": ["939791606331"],
    "ROLE_NAME": "am-tag-policy-notification-role",
    "EXPECTED_TAGS": {
        "Environment": ["Production", "Development", "Testing"],
        "Owner": ["TeamA", "TeamB"]
    },
    "SERVICES_TO_CHECK": [
        "ec2", "s3", "rds", "lambda", "dynamodb", "ecs", "ebs"
    ],
    "REGIONS_TO_CHECK": [
        "us-east-1", "us-west-1", "eu-west-1", "ap-southeast-1"
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

def get_resources_with_tags(credentials, tag_filters, regions, resource_arn_list):
    """Obtener recursos desde Tag Editor (resourcegroupstaggingapi)."""
    resources = []
    
    if not credentials:
        print("❗️ Credenciales no válidas. Saltando consulta de recursos.")
        return resources
    
    for region in regions:
        try:
            tagging_client = boto3.client(
                'resourcegroupstaggingapi',
                region_name=region,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            
            next_token = None
            while True:
                if next_token:
                    response = tagging_client.get_resources(
                        TagFilters=tag_filters,
                        ResourceARNList=resource_arn_list,
                        PaginationToken=next_token
                    )
                else:
                    response = tagging_client.get_resources(
                        TagFilters=tag_filters,
                        ResourceARNList=resource_arn_list
                    )
                
                # ✅ Validar si hay resultados
                if 'ResourceTagMappingList' in response and response['ResourceTagMappingList']:
                    print(f"✅ [{region}] Recursos encontrados: {len(response['ResourceTagMappingList'])}")
                    resources.extend(response['ResourceTagMappingList'])
                else:
                    print(f"⚠️ [{region}] No se encontraron recursos etiquetados.")
                
                next_token = response.get('PaginationToken')
                if not next_token:
                    break
        except Exception as e:
            print(f"❗️ Error al obtener recursos en la región {region}: {str(e)}")
    
    return resources

def compare_tags(expected_tags, resource_tags):
    """Comparar etiquetas esperadas con las etiquetas del recurso."""
    resource_tag_dict = {tag['Key']: tag['Value'] for tag in resource_tags}
    
    for key, expected_values in expected_tags.items():
        if key not in resource_tag_dict:
            return False
        
        if resource_tag_dict[key] not in expected_values:
            return False
    
    return True

def lambda_handler(event, context):
    aws_accounts = config_data['AWS_ACCOUNTS']
    role_name = config_data['ROLE_NAME']
    expected_tags = config_data['EXPECTED_TAGS']
    services_to_check = config_data['SERVICES_TO_CHECK']
    regions_to_check = config_data['REGIONS_TO_CHECK']

    # ✅ Construcción de ARN para servicios seleccionados
    resource_arn_list = [
        f"arn:aws:{service}:*:*:*" for service in services_to_check
    ]

    # ✅ Construcción de filtros de etiquetas esperadas
    tag_filters = [
        {'Key': key, 'Values': values}
        for key, values in expected_tags.items()
    ]

    # ✅ Lista para recursos sin etiquetas correctas
    resources_with_missing_or_invalid_tags = []
    
    for account_id in aws_accounts:
        try:
            # ⚡️ Intentar asumir el rol para la cuenta
            credentials = get_assumed_role_credentials(account_id, role_name)
            
            # 🚨 Validación Crítica: Detener si no hay credenciales
            if not credentials:
                raise Exception(f"Error crítico: No se pudieron obtener credenciales para la cuenta {account_id}.")
            
            # ✅ Obtener recursos desde Tag Editor para cada región configurada
            resources = get_resources_with_tags(credentials, tag_filters, regions_to_check, resource_arn_list)
            
            # 🔍 Validar si los recursos cumplen con las etiquetas esperadas
            for resource in resources:
                resource_tags = resource.get('Tags', [])
                if not compare_tags(expected_tags, resource_tags):
                    resources_with_missing_or_invalid_tags.append({
                        'account_id': account_id,
                        'resource_arn': resource['ResourceARN'],
                        'tags': resource_tags
                    })
        
        except Exception as e:
            print(f"❗️ Error crítico: {str(e)}")
            return {
                'statusCode': 500,
                'body': json.dumps({'error': str(e)})
            }

    # 📚 Depuración para verificar cuántos recursos fueron encontrados
    print(f"✅ Recursos totales mal etiquetados: {len(resources_with_missing_or_invalid_tags)}")

    # 🎯 Si hay recursos con etiquetas faltantes o incorrectas
    if resources_with_missing_or_invalid_tags:
        return {
            'statusCode': 200,
            'body': json.dumps(resources_with_missing_or_invalid_tags, indent=2)
        }
    else:
        return {
            'statusCode': 200,
            'body': json.dumps('✅ Todos los recursos tienen las etiquetas correctas')
        }
