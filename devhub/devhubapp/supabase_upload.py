import mimetypes
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from django.conf import settings

SUPABASE_S3_ENDPOINT = settings.SUPABASE_S3_ENDPOINT  # must include /storage/v1/s3
SUPABASE_S3_REGION = settings.SUPABASE_S3_REGION
SUPABASE_BUCKET = settings.SUPABASE_BUCKET
SUPABASE_ACCESS_KEY = settings.SUPABASE_ACCESS_KEY
SUPABASE_SECRET_KEY = settings.SUPABASE_SECRET_KEY

def get_s3_client():
    return boto3.client(
        "s3",
        region_name=SUPABASE_S3_REGION,
        endpoint_url=SUPABASE_S3_ENDPOINT,
        aws_access_key_id=SUPABASE_ACCESS_KEY,
        aws_secret_access_key=SUPABASE_SECRET_KEY,
        config=Config(s3={"addressing_style": "path"}),
    )

def guess_content_type(filename):
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"

def upload_image_fileobj(file_obj, dest_path, bucket=None):
    bucket = bucket or SUPABASE_BUCKET
    content_type = guess_content_type(dest_path)
    file_obj.seek(0)

    client = get_s3_client()
    client.upload_fileobj(
        file_obj,
        bucket,
        dest_path,
        ExtraArgs={"ContentType": content_type},
    )
    return dest_path

def build_public_url(object_key, bucket=None):
    base = SUPABASE_S3_ENDPOINT.replace("/storage/v1/s3", "")
    return f"{base}/storage/v1/object/public/{bucket or SUPABASE_BUCKET}/{object_key}"
