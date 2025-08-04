# Set up logging
import csv
import logging
import os
import tempfile

import boto3
import pandas as pd

from kiteconnect import KiteConnect
from kiteconnect.exceptions import TokenException

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

kite_client_creds = None
kite_client = None
s3_client = None
ACCESS_TOKEN_BUCKET_NAME = 'syncit-access-token'
ACCESS_TOKEN_FILE_PATH = 'access_token.csv'

def read_aws_credentials_from_csv():
    aws_creds_file_path = "sync-it_accessKeys.csv"
    logger.info(f"AWS Creds file path: {aws_creds_file_path}")
    try:
        # Load the CSV file
        df = pd.read_csv(aws_creds_file_path)

        # Extract the access key and secret key from the first row
        access_key = df.loc[0, 'Access key ID']
        secret_key = df.loc[0, 'Secret access key']

        return access_key, secret_key
    except Exception as e:
        print("Error reading AWS credentials:", e)
        return None, None

def get_secret(parameter_name):
    access_key, secret_key = read_aws_credentials_from_csv()
    logger.info(f"AWS Access key: {access_key}, Secret Key: {secret_key}")
    """Fetch a parameter from AWS SSM Parameter Store."""
    try:
        ssm_client = boto3.client('ssm',
                                  aws_access_key_id=access_key,
                                  aws_secret_access_key=secret_key,
                                  region_name=os.getenv('AWS_REGION', 'us-east-2'))
        response = ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
        logger.info(f"SSM Response Received: {response}")
        return response['Parameter']['Value']
    except Exception as e:
        logger.error(f"Error in fetching SSM param: {e}")
        return "Invalid SSM Secret"

def get_s3_client():
    global s3_client
    if s3_client is not None:
        return s3_client
    access_key, secret_key = read_aws_credentials_from_csv()
    logger.info(f"AWS Access key: {access_key}, Secret Key: {secret_key}")
    """Creating S3 Client"""
    s3_client = boto3.client('s3',
                             aws_access_key_id=access_key,
                             aws_secret_access_key=secret_key,
                             region_name=os.getenv('AWS_REGION', 'us-east-2'))
    return s3_client

def extract_access_token():
    try:
        # Download CSV from S3 to a temporary file
        local_file_path = os.path.join(tempfile.gettempdir(), os.path.basename(ACCESS_TOKEN_FILE_PATH))
        get_s3_client().download_file(ACCESS_TOKEN_BUCKET_NAME, ACCESS_TOKEN_FILE_PATH, local_file_path)

        # Load the CSV file
        df = pd.read_csv(local_file_path)

        # Check if 'access_token' column exists
        if "access_token" in df.columns:
            # Return the first access token found in the CSV
            return df["access_token"].iloc[0]
        else:
            print("Error: 'access_token' column not found in the file.")
            return None
    except Exception as e:
        print(f"Error reading file from S3: {e}")
        return None

def is_access_token_valid(access_token, api_key):
    global kite_client_creds
    if kite_client_creds is None:
        kite_client_creds = KiteConnect(api_key=api_key)

    try:
        kite_client_creds.set_access_token(access_token)
        kite_client_creds.profile()  # Make an authenticated call
        logger.info("File access token is still valid, returning it")
        return True  # Token is valid
    except TokenException:
        logger.info("File access token has expired.")
        return False  # Token has expired

def generate_access_token(api_key, api_secret, request_token):
    try:
        # Generate the session (access token)
        kite = KiteConnect(api_key=api_key)
        logger.info(kite.login_url())
        data = kite.generate_session(request_token, api_secret=api_secret)
        access_token = data["access_token"]

        # Save access token to a temporary CSV file
        local_file_path = f"/tmp/{os.path.basename(ACCESS_TOKEN_FILE_PATH)}"
        with open(local_file_path, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["api_key", "access_token"])  # Headers
            writer.writerow([api_key, access_token])  # Data row

        # Upload the CSV to S3
        get_s3_client().upload_file(local_file_path, ACCESS_TOKEN_BUCKET_NAME, ACCESS_TOKEN_FILE_PATH)
        logger.info("Access Token generated and saved to S3")

        return access_token
    except Exception as e:
        logger.error("Error generating access token:", e)
        return "Invalid Access token"

def retrieve_access_token(api_key, api_secret, request_token):
    access_token = extract_access_token()
    logger.info(f"Access token extracted from file: {access_token}")
    if is_access_token_valid(access_token, api_key):
        logger.info(f"Access token read from file: {access_token}")
        return access_token
    logger.info(f"Access token extracted from file: {access_token} is invalid, generating new")
    access_token = generate_access_token(api_key, api_secret, request_token)
    logger.info(f"Access token generated afresh and saved to file: {access_token}")
    return access_token


def get_kite_client():
    global kite_client
    if kite_client is not None:
        return kite_client
    api_key = get_secret('finweb.api_key')
    api_secret = get_secret('finweb.api_secret')
    request_token = get_secret('finweb.request_token')
    logger.info(f"Within Get Kite Client:: "
                f"API Key: {api_key}, API secret: {api_secret}, Request Token: {request_token}")
    access_token = retrieve_access_token(api_key, api_secret, request_token)
    kite_client = KiteConnect(api_key=api_key)
    kite_client.set_access_token(access_token)
    return kite_client