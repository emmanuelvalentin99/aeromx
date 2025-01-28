import boto3
import json
import os

# Define las etiquetas requeridas y sus valores permitidos
REQUIRED_TAGS = {
    "Area": [
        "Cargo", "Mantenimiento", "Operaciones", "Aeropuertos", "Seguridad-aerea",
        "Revenie-accounting", "Call-center", "DataAnalytics", "Estrategia-de-ingresos",
        "Pricing", "Svoc", "Voc", "Revenue-management", "Marketing"
    ],
    "Environment": ["dev", "qa", "prod"],
    "Vertical": ["comm", "cust", "corp", "cha-beth", "svoe", "oper", "ia", "de"],
    "Ambiente": ["PD", "Q", "DE"],
    "ImpactoANegocio": ["Tier1", "Tier2", "Tier3", "Tier4"],
    "lcf": ["IF", "DP", "NA"],
    "map-migrated": ["d-server-03cd3bbblu0msp"],
    "AreaResponsable": ["DA-AI"],
    "CentroDeCosto": ["121001"],
    "DuenoDeLaCuenta": ["amsoportedatalake@aeromexico.com"],
    "Proyecto": ["Datalake"],
    "Aplicacion": ["Datalake"]
}

# Inicializa los servicios que serán analizados
SERVICES = ["ec2", "s3", "dynamodb", "rds", "lambda", "sns"]

def assume_role(account_id):
    """Asume un rol en otra cuenta y devuelve un cliente de sesión."""
    sts_client = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/LambdaAuditRole"
    
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AuditSession"
        )
        credentials = response["Credentials"]
        session = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"]
        )
        return session
    except Exception as e:
        print(f"Error al asumir rol en la cuenta {account_id}: {str(e)}")
        return None

def lambda_handler(event, context):
    account_ids = os.environ.get("ACCOUNT_IDS", "")
    if not account_ids:
        return {
            "statusCode": 400,
            "body": "No se encontraron cuentas en la variable de entorno ACCOUNT_IDS."
        }
    
    account_ids = account_ids.split(",")
    missing_tags = []

    for account_id in account_ids:
        print(f"Analizando recursos en la cuenta {account_id}")
        session = assume_role(account_id.strip())
        if not session:
            continue
        
        for service in SERVICES:
            try:
                resources = list_resources(session, service)
                for resource in resources:
                    tags = get_resource_tags(session, service, resource)
                    missing = validate_tags(tags, resource, service, account_id)
                    if missing:
                        missing_tags.extend(missing)
            except Exception as e:
                print(f"Error analizando el servicio {service} en la cuenta {account_id}: {str(e)}")
    
    # Ordenar los resultados
    sorted_missing_tags = sorted(missing_tags, key=lambda x: (x['AccountId'], x['Service'], x['ResourceId']))
    
    # Imprimir o enviar los resultados
    print(json.dumps(sorted_missing_tags, indent=2))
    return {
        "statusCode": 200,
        "body": json.dumps(sorted_missing_tags)
    }

def list_resources(session, service):
    """Lista los recursos del servicio especificado usando una sesión."""
    client = session.client(service)
    resources = []
    
    if service == "ec2":
        instances = client.describe_instances()
        for reservation in instances["Reservations"]:
            for instance in reservation["Instances"]:
                resources.append(instance["InstanceId"])
    elif service == "s3":
        buckets = client.list_buckets()
        resources = [bucket["Name"] for bucket in buckets["Buckets"]]
    elif service == "dynamodb":
        tables = client.list_tables()
        resources = tables["TableNames"]
    elif service == "rds":
        dbs = client.describe_db_instances()
        resources = [db["DBInstanceIdentifier"] for db in dbs["DBInstances"]]
    elif service == "lambda":
        functions = client.list_functions()
        resources = [function["FunctionName"] for function in functions["Functions"]]
    elif service == "sns":
        topics = client.list_topics()
        resources = [topic["TopicArn"] for topic in topics["Topics"]]
    
    return resources

def get_resource_tags(session, service, resource_id):
    """Obtiene las etiquetas de un recurso específico usando una sesión."""
    client = session.client(service)
    tags = {}
    
    try:
        if service == "ec2":
            response = client.describe_tags(
                Filters=[{"Name": "resource-id", "Values": [resource_id]}]
            )
            tags = {tag["Key"]: tag["Value"] for tag in response["Tags"]}
        elif service == "s3":
            response = client.get_bucket_tagging(Bucket=resource_id)
            tags = {tag["Key"]: tag["Value"] for tag in response["TagSet"]}
        elif service == "dynamodb":
            response = client.list_tags_of_resource(ResourceArn=resource_id)
            tags = {tag["Key"]: tag["Value"] for tag in response["Tags"]}
        elif service == "rds":
            response = client.list_tags_for_resource(ResourceName=resource_id)
            tags = {tag["Key"]: tag["Value"] for tag in response["TagList"]}
        elif service == "lambda":
            response = client.list_tags(Resource=resource_id)
            tags = response["Tags"]
        elif service == "sns":
            response = client.list_tags_for_resource(ResourceArn=resource_id)
            tags = response["Tags"]
    except Exception as e:
        print(f"Error obteniendo etiquetas para {service} - {resource_id}: {str(e)}")
    
    return tags

def validate_tags(tags, resource_id, service, account_id):
    """Valida las etiquetas de un recurso contra las requeridas."""
    missing = []
    
    for key, allowed_values in REQUIRED_TAGS.items():
        if key not in tags or (allowed_values and tags[key] not in allowed_values):
            missing.append({
                "AccountId": account_id,
                "Service": service,
                "ResourceId": resource_id,
                "MissingTag": key,
                "ExpectedValues": allowed_values,
                "ActualValue": tags.get(key, "None")
            })
    
    return missing
