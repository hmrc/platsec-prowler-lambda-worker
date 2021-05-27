from src.platsec.compliance.prowler_pipeline import (execute_validation, get_config, get_aws_client,
                                                     run_prowler, check_output_folder, create_aws_environment,
                                                     execute_diff_generation, execute_filters, execute_save_diff,
                                                     execute_clean_up)
from src.platsec.compliance.prowler_exceptions import (PipelineValidationPhaseException, ProwlerExecutionError)
from src.platsec.compliance.prowler import (ProwlerConfig, ProwlerExecutionRun)
from src.platsec.compliance.prowler_filters import pretty_print
from botocore.client import BaseClient
from typing import List


def lambda_handler(event, context):
    """
    Main entry point for the Lambda Function.
    This is called at the start by the Lambda Environment
    """
    execute_pipeline(event)


def execute_pipeline(json_data: str):
    """
    Executes a pipeline containing all the phases
    necessary to produce a difference report
    """
    print(f"DEBUG **** Executing Pipeline")
    prowler_config = process_config()

    if prowler_config.mode == "detached":
        print(f"DEBUG **** Executing Pipeline in {prowler_config.mode} mode")
    else:
        print(f"DEBUG **** Executing Pipeline in {prowler_config.mode} mode")
        prowler_run = process_validation(json_data, prowler_config.group_location, prowler_config.default_groups)
        s3_client = get_aws_client()
        print(f"DEBUG **** Executing Prowler in Pipeline for {prowler_run.account_id}, {prowler_config.region}")
        process_prowler(prowler_run.account_id, prowler_run.new_report_name,
                        prowler_config.region, prowler_config.bucket_name, prowler_config.script_location,
                        prowler_run.groups)
        print(f"DEBUG: **** Executing AWS validation in Pipeline for {prowler_run.account_id}")
        process_aws_validation(prowler_config.bucket_name, prowler_run.account_id, s3_client)
        print(f"DEBUG **** Executing Difference creation in Pipeline for {prowler_run.account_id}")
        diff_data = process_diff_generation(prowler_config.bucket_name, prowler_run.account_id, s3_client)
        if diff_data == "":
            print(f"DEBUG **** No Difference created in Pipeline for {prowler_run.account_id}")
        else:
            print(f"DEBUG **** Applying filters to difference data for {prowler_run.account_id}")
            filter_list = [pretty_print]
            filtered_diff = process_apply_filters(diff_data, filter_list)
            print(f"DEBUG **** Saving difference data for {prowler_run.account_id}")
            execute_save_diff(filtered_diff, prowler_config.bucket_name, prowler_run.account_id,
                              s3_client)
            print(f"DEBUG **** Cleaning up AWS for {prowler_run.account_id}")
            execute_clean_up(prowler_config.bucket_name, prowler_run.account_id, s3_client)

    print(f"DEBUG **** Finished Executing Pipeline")


def process_config() -> ProwlerConfig:
    """
    Returns a class object with config items retrieve from
    Environment variables.  This allows the Lambda function to
    specify
    EXEC_MODE := detached or attached
    S3_BUCKET := Bucket name that stores difference report
    GROUPS_LOCATION := Location of groups definitions in Prowler
    DEFAULT_GROUPS := Name of a default group to always run
    DEFAULT_REGION := Name of the AWS Region Lambda should run in
    """
    return get_config()


def process_validation(json_data: str, group_location: str, default_group: str) -> ProwlerExecutionRun:
    """
    Runs the validation stage of the pipeline and is responsible
    for taking the SQS event message and checking
    1. An account has been supplied
    2. Groups are valid and are defined
    3. Retrieving Account Name and Account Id and Groups from the message
    4. Creating a report name for the Prowler execution report
    """
    try:
        phase_outcome = execute_validation(json_data, group_location, default_group)
        return phase_outcome

    except PipelineValidationPhaseException as error:
        print(f"DEBUG **** process validation error {error}")
        raise error


def process_prowler(account_number: str, report_name: str, region: str, bucket_name: str,
                    groups_location: str, groups: list):
    """
    Executes prowler with the supplied values from
    the validation phase
    """
    run_status = run_prowler(account_number, report_name, region, bucket_name, groups_location, groups)
    if not run_status:
        raise ProwlerExecutionError("Prowler failed to execute")


def process_aws_validation(bucket_name: str, account_id: str, s3_client: BaseClient):
    """
    Validates AWS Environment by
    1. Checks if an S3 path for the account id exists
    2. Creates the folder if the path doesnt exist
    """
    folder_exists = check_output_folder(bucket_name, account_id, s3_client)
    if not folder_exists:
        create_aws_environment(bucket_name, account_id, s3_client)


def process_diff_generation(bucket_name: str, account_id: str, s3_client: BaseClient) -> str:
    """
    Creates the difference report from the two
    exiting prowler execution reports.
    Returns the difference data for filtering in the next
    stage of the pipeline.
    """
    diff_data = execute_diff_generation(bucket_name, account_id, s3_client)
    return diff_data


def process_apply_filters(diff_data: str, filter_list: List) -> str:
    """
    Filters the difference output by applying a list
    of filter functions defined in the prowler_filters.py
    file.
    """
    filtered_data = execute_filters(diff_data, filter_list)
    return filtered_data


def process_save_diff(filtered_diff: str, bucket_name: str, account_id: str, s3_client: BaseClient) -> bool:
    """
    Saves the filtered difference data to
    the S3 output bucket.
    """
    file_created = execute_save_diff(filtered_diff, bucket_name, account_id, s3_client)
    return file_created


def process_clean_up(bucket_name: str, account_id: str, s3_client: BaseClient):
    """
    Cleans up the AWS S3 bucket to make sure the
    correct number of files is left for the
    next run of the lambda function.
    """
    execute_clean_up(bucket_name, account_id, s3_client)
