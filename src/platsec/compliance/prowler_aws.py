import logging
import boto3
from typing import Any, Dict
from botocore.exceptions import ClientError, BotoCoreError
from botocore.client import BaseClient
from src.platsec.compliance.prowler_exceptions import (
    AwsBucketPathCreateException,
    AwsProwlerFileException,
    AwsBotoAuthException,
)

# Create a custom logger
logger = logging.getLogger("prowler_aws")
c_handler = logging.StreamHandler()
c_format = logging.Formatter("%(name)s - %(levelname)s - %(message)s")
c_handler.setFormatter(c_format)
logger.addHandler(c_handler)


def boto3_auth(
    mfa: str, username: str, role: str, account: str, aws_sts_endpoint: str
) -> Any:
    try:
        return boto3.client(
            service_name="sts", endpoint_url=aws_sts_endpoint
        ).assume_role(
            DurationSeconds=3600,
            RoleArn=f"arn:aws:iam::{account}:role/{role}",
            RoleSessionName=f"Boto3AssumingRole{role}",
            SerialNumber=f"arn:aws:iam::{account}:mfa/{username}",
            TokenCode=mfa,
        )
    except (BotoCoreError, ClientError):
        raise AwsBotoAuthException


def setup_s3_client_lambda() -> BaseClient:
    return boto3.client(service_name="s3")


def setup_s3_client(mfa: Dict[Any, Any], aws_s3_endpoint: str) -> BaseClient:
    return boto3.client(
        service_name="s3",
        endpoint_url=aws_s3_endpoint,
        aws_access_key_id=mfa["Credentials"]["AccessKeyId"],
        aws_secret_access_key=mfa["Credentials"]["SecretAccessKey"],
        aws_session_token=mfa["Credentials"]["SessionToken"],
    )


def setup_sqs_client(mfa: Dict[Any, Any], aws_sqs_endpoint: str) -> BaseClient:
    return boto3.client(
        service_name="sqs",
        endpoint_url=aws_sqs_endpoint,
        aws_access_key_id=mfa["Credentials"]["AccessKeyId"],
        aws_secret_access_key=mfa["Credentials"]["SecretAccessKey"],
        aws_session_token=mfa["Credentials"]["SessionToken"],
    )


def get_previous_report(bucket_name: str, key: str, client: BaseClient) -> str:
    """
    Gets the previous accounts report
    """
    response = client.get_object(Bucket=bucket_name, Key=key)
    return response


def download_report(
    bucket_name: str, client: BaseClient, report: str, location: str
) -> bool:
    """
    Downloads the original report
    to the temporary work area
    """
    response = client.download_file(
        Bucket=bucket_name, FileName=report, Location=location
    )
    return response


def check_diff_required(account_id: str, bucket_name: str, client: BaseClient) -> bool:
    """
    Checks to see if a difference
    Is required or not.
    """
    try:
        response = client.list_objects(Bucket=bucket_name, Prefix=account_id)
        if "Contents" in response:
            if len(response["Contents"]) > 2:
                diff_required = True
            else:
                diff_required = False
            return diff_required
    except (BotoCoreError, ClientError) as error:
        logger.error(f"{account_id} failed to generate diff report {error}")
        raise AwsProwlerFileException(error)


def copy_report(
    file_name: str, account_name: str, bucket_name: str, client: BaseClient
) -> bool:
    """
    Copies a generated report to the output location
    """
    report_copied = False
    try:
        report_copied = client.upload_file(
            File=file_name, Bucket=bucket_name, Prefix=account_name
        )
    finally:
        return report_copied


def check_output_folder(
    bucket_name: str, account_id: str, s3_client: BaseClient
) -> bool:
    """
    Checks for a S3 path containing the id of
    the account
    """
    folder_exists = False
    try:
        response = s3_client.list_objects_v2(
            Bucket=bucket_name, Delimiter="\\", Prefix=account_id
        )
        if "Contents" in response["ResponseMetadata"]:
            folder_exists = True

        print(response)
        return folder_exists
    except (BotoCoreError, ClientError) as error:
        logger.error(f"{account_id}  output folder")
        raise AwsBucketPathCreateException(error)


def get_filenames(bucket_name: str, account_id: str, s3_client: BaseClient) -> list:
    """
    Returns a list of text filenames to perform
    the difference on.  There should always only be three items
    in the contents response the folder and two files.
    """
    reports = []
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=account_id)
        if "Contents" in response:
            file_count = len(response["Contents"])
            print(f"DEBUG*** FileCount Message {response}")
            for file in range(0, file_count):
                if ".txt" in response["Contents"][file]["Key"]:
                    file_object = response["Contents"][file]["Key"]
                    file_name = file_object.split("/")
                    reports.append(file_name[1])
            return reports
    except (BotoCoreError, ClientError) as error:
        raise AwsProwlerFileException(error)


def delete_old_files(
    bucket_name: str, file: str, s3_client: BaseClient
) -> str:
    """
    Deletes files from the last run
    Leaving only the newest file
    """
    response = ""

    try:
        file_check = file.split("/")
        if ".txt" in file_check[1]:
            response = s3_client.delete_object(Bucket=bucket_name, Key=file)
            print(f"DEBUG*** File Deleted {file}")
        return response
    except (BotoCoreError, ClientError) as error:
        raise AwsProwlerFileException(error)


def get_file_contents(
    bucket_name: str, account_id: str, file_name: str, s3_client: BaseClient
) -> str:
    """
    Returns and reads the contents of the specified file
    To be able to do a diff on them
    """
    contents = ""
    try:
        file_object = s3_client.get_object(
            Bucket=bucket_name, Key=account_id + "/" + file_name
        )
        contents = file_object["Body"].read()
    except TypeError as error:
        raise error
    except Exception as error:
        raise error
    finally:
        return contents


def create_output_folder(
    bucket_name: str, account_id: str, s3_client: BaseClient
) -> str:
    """
    Creates an S3 path object made up of the
    AWS Account Id
    """
    try:
        response = s3_client.put_object(Bucket=bucket_name, Key=account_id + "/")
        return response
    except (BotoCoreError, ClientError) as error:
        raise AwsBucketPathCreateException(error)


def get_sorted_file_list(
    bucket_name: str, s3_client: BaseClient
) -> list:
    """
    Returns an ordered list of files
    by modified date
    """
    try:
        get_last_modified = lambda file: int(file["LastModified"].strftime("%s"))

        files = s3_client.list_objects_v2(Bucket=bucket_name)["Contents"]
        ordered_files = [file["Key"] for file in sorted(files, key=get_last_modified)]

        return ordered_files

    except Exception as error:
        raise error


def save_diff(
    bucket_name: str,
    account_id: str,
    file_name: str,
    diff_data: str,
    s3_client: BaseClient,
) -> str:
    """
    Saves the filtered difference data to the
    S3 output bucket
    """
    try:
        response = s3_client.put_object(
            Body=diff_data, Bucket=bucket_name, Key=account_id + "/" + file_name + ".diff"
        )
        return response
    except (BotoCoreError, ClientError) as error:
        raise AwsProwlerFileException(error)
