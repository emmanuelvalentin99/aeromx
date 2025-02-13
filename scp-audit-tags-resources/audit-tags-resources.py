import boto3
import pandas as pd
from botocore.exceptions import ClientError
import time
import openpyxl
from io import BytesIO
from datetime import datetime
 
# Configura los servicios de AWS
athena_client = boto3.client('athena')
s3_client = boto3.client('s3')
ses_client = boto3.client('ses')
bucket_name = "tu-bucket-s3"  # S3 donde se guardarán los resultados de Athena
output_location = f"s3://{bucket_name}/resultados/"
 
# Parámetros de consulta Athena
database_name = 'tu_base_de_datos'
query = """
    SELECT * FROM tu_tabla LIMIT 10;
"""
 
# Dirección de correo
email_from = "tu_correo@dominio.com"
email_to = "correo_destino@dominio.com"
subject = "Resultados de consulta Athena"
body_text = "Adjunto los resultados de la consulta Athena en formato Excel."
 
def execute_athena_query():
    # Ejecutar la consulta en Athena
    response = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={
            'Database': database_name
        },
        ResultConfiguration={
            'OutputLocation': output_location,
        }
    )
    # Obtener el ID de la ejecución
    query_execution_id = response['QueryExecutionId']
    return query_execution_id
 
def wait_for_query_to_complete(query_execution_id):
    # Esperar hasta que la consulta termine
    while True:
        response = athena_client.get_query_execution(QueryExecutionId=query_execution_id)
        status = response['QueryExecution']['Status']['State']
        if status == 'SUCCEEDED':
            print("Consulta ejecutada con éxito")
            return True
        elif status == 'FAILED':
            print("La consulta falló")
            return False
        elif status == 'CANCELLED':
            print("La consulta fue cancelada")
            return False
        # Esperar un poco antes de volver a verificar
        time.sleep(5)
 
def fetch_results_from_s3(query_execution_id):
    # Verificar que los resultados de la consulta están en S3
    result_file_path = f"resultados/{query_execution_id}.csv"
    s3_response = s3_client.get_object(Bucket=bucket_name, Key=result_file_path)
    return s3_response['Body'].read()
 
def create_excel_from_csv(csv_data):
    # Crear un DataFrame de pandas a partir de los resultados en CSV
    df = pd.read_csv(BytesIO(csv_data))
 
    # Crear un archivo Excel en memoria
    excel_buffer = BytesIO()
    with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Resultados')
    excel_buffer.seek(0)
    return excel_buffer
 
def send_email_with_attachment(excel_buffer):
    # Enviar el archivo Excel como adjunto por email usando SES
    try:
        response = ses_client.send_raw_email(
            Source=email_from,
            Destinations=[email_to],
            RawMessage={
                'Data': create_email_message(excel_buffer)
            }
        )
        print(f"Correo enviado: {response}")
    except ClientError as e:
        print(f"Error al enviar el correo: {e}")
 
def create_email_message(excel_buffer):
    # Crear el cuerpo del mensaje con el adjunto Excel
    from email.mime.multipart import MIMEMultipart
    from email.mime.base import MIMEBase
    from email import encoders
 
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = email_from
    msg['To'] = email_to
    msg.attach(MIMEText(body_text, 'plain'))
 
    part = MIMEBase('application', 'octet-stream')
    part.set_payload(excel_buffer.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment; filename="resultados_athena.xlsx"')
    msg.attach(part)
 
    return msg.as_string()
 
def lambda_handler(event, context):
    # Ejecutar la consulta de Athena
    query_execution_id = execute_athena_query()
    # Esperar a que la consulta termine
    if wait_for_query_to_complete(query_execution_id):
        # Obtener los resultados de S3
        csv_data = fetch_results_from_s3(query_execution_id)
        # Crear el archivo Excel desde los resultados CSV
        excel_buffer = create_excel_from_csv(csv_data)
        # Enviar el archivo Excel por correo electrónico
        send_email_with_attachment(excel_buffer)