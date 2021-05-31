from src.platsec.compliance.prowler import (ProwlerExecutionRun, ProwlerConfig)
from src.platsec.compliance.prowler_exceptions import (
    PipelineValidationPhaseException,
    AwsBucketPathCreateException,
    AwsProwlerFileException)
from src.platsec.compliance.prowler import (
    get_prowler_config,
    check_records,
    check_accounts,
    extract_body,
    get_accountinfo,
    get_account_name,
    get_groups,
    validate_groups,
    create_new_report_name,
    execute_prowler,
    create_diff,
    create_new_diff_name,
    get_group_ids,
    extract_group_ids
)
from src.platsec.compliance.prowler_aws import (check_output_folder, create_output_folder,
                                                get_filenames, get_file_contents, save_diff,
                                                get_sorted_file_list, delete_old_files)
from src.platsec.compliance.prowler_aws import (setup_s3_client_lambda)
from botocore.client import BaseClient
from functools import reduce


def execute_validation(json_data: str, group_location: str, default_group: str) -> ProwlerExecutionRun:
    """
    Called from the pipeline execution phase and returns a ProwlerExecutionRun object
    that has extracted the relevant parts of the incoming SQS message in order
    to run prowler
    """
    try:
        prowler_run = ProwlerExecutionRun()
        prowler_run.record_count = check_records(json_data)
        prowler_run.account_count = check_accounts(json_data)
        if prowler_run.account_count == 0:
            raise PipelineValidationPhaseException("No accounts to process")
        prowler_run.msgbody = extract_body(json_data)
        prowler_run.account_id = get_accountinfo(prowler_run.msgbody)
        prowler_run.account_name = get_account_name(prowler_run.msgbody)
        prowler_run.groups = get_groups(prowler_run.msgbody, default_group)
        prowler_run.new_report_name = create_new_report_name(prowler_run.account_id)
        validate_groups(prowler_run.groups, group_location, default_group)
        prowler_run.group_contents = get_group_ids(group_location, prowler_run.groups)
        prowler_run.group_ids = extract_group_ids(prowler_run.group_contents)
        return prowler_run
    except Exception as error:
        print(f"DEBUG *** execute_validation err {error}")
        raise PipelineValidationPhaseException(error)


def get_config() -> ProwlerConfig:
    """
    Returns OS Environment config options.
    """
    prowler_config = get_prowler_config()
    return prowler_config


def get_aws_client() -> BaseClient:
    """
    Returns a AWS Boto3 s3 client that can
    run within a serverless environment.
    """
    return setup_s3_client_lambda()


def run_prowler(account_number: str, report_name: str, region: str, bucket_name: str, groups_location: str, groups: list) -> bool:
    """
    Executes the prowler program with
    values created from the validation stage of pipeline.
    """
    executed = execute_prowler(account_number, report_name, region, bucket_name, groups_location, groups)
    return executed


def execute_aws_validation(bucket_name: str, account_id: str, s3_client: BaseClient) -> bool:
    """
    Checks that an output folder exists
    for the account id
    """
    folder_exists = check_output_folder(bucket_name, account_id, s3_client)
    return folder_exists


def create_aws_environment(bucket_name: str, account_id: str, s3_client: BaseClient) -> bool:
    """
    Creates in the S3 bucket a path which is
    made up of the account id from AWS.
    """
    bucket_created = False
    try:
        create_output_folder(bucket_name, account_id, s3_client)
        bucket_created = True
        return bucket_created
    except AwsBucketPathCreateException:
        return bucket_created


def execute_diff_generation(bucket_name: str, account_id: str, s3_client: BaseClient) -> str:
    """
    Responsible for generating diff reports
    We should only produce a difference if the filecount
    is equal to 2 because there should be two text files
    """

    files_list = get_filenames(bucket_name, account_id, s3_client)
    print(f"DEBUG:*** execute_diff_generation file_count {len(files_list)}")
    if len(files_list) == 2:
        first_prowler_report = get_file_contents(bucket_name, account_id, files_list[0], s3_client)
        second_prowler_report = get_file_contents(bucket_name, account_id, files_list[1], s3_client)
        diff_data = create_diff(first_prowler_report.decode('ascii'), second_prowler_report.decode('ascii'))
        return diff_data
    else:
        return ""


def execute_filters(diff_data: str, filter_list: list) -> str:
    """
    Applies filter functions to the difference output
    """
    filters = filter_list
    return reduce(lambda m, f: f(m), filters, diff_data)


def execute_save_diff(filtered_diff_data: str, bucket_name: str, account_id: str, s3_client: BaseClient) -> bool:
    """
    Saves the filtered difference text to the S3 bucket
    """
    file_created = False
    try:
        diff_filename = create_new_diff_name(account_id)
        save_diff(bucket_name, account_id, diff_filename, filtered_diff_data, s3_client)
        file_created = True
        return file_created
    except AwsProwlerFileException:
        return file_created


def execute_clean_up(bucket_name: str, account_id:str, s3_client: BaseClient):
    """
    Deletes oldest prowler execution report as its no longer
    needed.
    N.B because S3 is object storage the path is also counted in
    the file listing so for additional runs we should only delete when th
    file count is four leaving a file count of three.  This is made up of
    1) The Path file object which is the account id
    2) The newest prowler execution file
    3) The difference report
    """
    file_list = get_sorted_file_list(bucket_name, s3_client)
    print(f"DEBUG*** execute_clean_up file {file_list[0]}")
    if len(file_list) > 3:
        delete_old_files(bucket_name, file_list[0], s3_client)

