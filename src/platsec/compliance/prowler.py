"""
Contains the  functions that will
process and produce the diff file for prowler
"""
import logging
import os
import time
import subprocess
import difflib
import json
from typing import List, Dict

# Create a custom logger
logger = logging.getLogger("prowler")
c_handler = logging.StreamHandler()
c_format = logging.Formatter("%(name)s - %(levelname)s - %(message)s")
c_handler.setFormatter(c_format)
logger.addHandler(c_handler)


def extract_body(event: Dict) -> dict:
    """
    Extracts the body from the message
    """
    if event == "" or event is None:
        raise ValueError("SQS Message has no body element")
    else:
        for record in event['Records']:
            payload = record["body"]
            if isinstance(payload, str):
                converted_payload = json.loads(payload)
                return converted_payload
            return payload


def get_accountinfo(msg: dict) -> str:
    """
    Returns a dictionary containing the
    account id and an array of prowler group checks.
    """
    if msg == "":
        raise IndexError
    else:
        try:
            account_id = msg['Id']
            return account_id
        except KeyError as err:
            raise err


def get_account_name(msg: dict) -> str:
    """
    Returns the account name
    """
    try:
        account_name = msg['Name']
        return account_name
    except KeyError as err:
        raise err


def check_accounts(msg: dict) -> int:
    """
    Returns the number of accounts to
    process.
    The incoming msg is a string that contains the
    Account Id, Groups and Account name
    """
    accounts = 0
    print(f"DEBUG --- check_account msg parameter {msg}")
    if msg != "":
        accounts = len(msg[0])

    return accounts


def check_records(msg: dict) -> int:
    """
    Returns the number of records
    sent in the SQS message
    """
    records = 0
    if msg is not None:
        records = len(msg[0])

    if records != 1:
        raise ValueError("Not expected single record")

    return records


def validate_groups(groups: List, path: str, default_group: str) -> list:
    """
    Validates that the specified groups exist
    in the lib folder of the prowler implementation
    or throw a value error if not.
    """
    print(f"DEBUG *** groups {groups} path {path} default {default_group}")
    check_list = os.listdir(path)
    process_list = [group for group in groups if group in check_list]
    print(f" Process list {process_list}")
    if len(process_list) == 0:
         process_list.append(default_group)
    return process_list


def execute_prowler(account_number: str, report_name: str, region: str, bucket_name: str, prowler_directory: str,
                    groups: List) -> bool:
    report_generated = False

    try:
        print(f"DEBUG *** {prowler_directory} creating attempt")
        print(f"DEBUG *** prowler_directory {prowler_directory}")

        if os.getcwd() is not prowler_directory:
            path_parent = os.path.dirname(os.getcwd())
            print(f"DEBUG xxx new dir {path_parent}")
            print(f"DEBUG Attempting ch dir {path_parent}")
            os.chdir(path_parent)

        prowler_cmd = "./prowler"
        if len(groups) == 1:
            group_list = groups[0]
            print(f"DEBUG --- execute_prowler groups_list {group_list}")
        else:
            group_list = ','.join(groups)

        print(f"DEBUG *** Executing Prowler with group {group_list}")

        p1 = subprocess.Popen(
            [prowler_cmd, "-r", region, "-g", group_list, "-M", "text"],
            stdout=subprocess.PIPE,
        )
        p2 = subprocess.run(
            [
                "aws",
                "s3",
                "cp",
                "-",
                f"s3://{bucket_name}/{account_number}/{report_name}.txt",
            ],
            stdin=p1.stdout,
        )
        report_generated = True
    except Exception as error:
        print(os.getcwd())
        print(f"EXCEPTION **** {error}")
    finally:
        return report_generated


def check_platsec_group(config: str, group: str) -> bool:
    """
    Checks to see if the mandatory
    platsec group is in the config
    """
    group_present = group in config["Groups"]
    return group_present


def create_diff(original_report: str, generated_report: str) -> str:
    """
    Generates a difference on the
    Two Files
    """
    try:
        diff_text = ""
        for diff in difflib.unified_diff(original_report, generated_report):
            diff_text += diff + ","
        return diff_text
    except Exception as error:
        logger.error(f"did not generate diff report {error}")
        raise error


def create_diff_v2(original_report: str, generated_report: str) -> str:
    """
    Generates a difference on the
    Two Files
    """
    try:
        d = difflib.Differ()
        diff = d.compare(original_report.split(), generated_report.split())
        diff_text = '\n'.join(diff)
        return diff_text
    except Exception as error:
        logger.error(f"did not generate diff report {error}")
        raise error


def get_groups(records_data: dict, default_group: str) -> List:
    """
    Returns the specified groups in the
    SQS Message
    """
    groups = records_data["Groups"]
    try:
        if len(groups) > 0:
            return groups
        else:
            return [default_group]
    except IndexError as err:
        raise err


def get_group_ids(path: str, group_filenames: list) -> List:
    """
    Returns a list of group_ids from
    the specified path
    """
    print(f"DEBUG --- get_group_ids {path}, {len(group_filenames)}")
    group_ids = []
    for file in group_filenames:
        path_to_check = os.path.join(path, file)
        print(f"DEBUG -- get_group_ids path to check {path_to_check}")
        if os.path.exists(path_to_check):
            os.chdir(path)
            f = open(file, "r")
            file_contents = f.readlines()
            group_ids.append(file_contents)
            f.close()
        else:
            print("No files for that group")
    return group_ids


def extract_group_ids(groups: list) -> List:
    """
    Extracts the groups ids from a list
    containing specified groups file contents
    """
    print(f"Groups in extract_group_ids{groups[0]}")
    group_ids = []
    for group in groups:
        for item in group:
            if 'GROUP_ID' in item:
                group_parts = item.split("'")
                group_id_part = group_parts[1]
                group_ids.append(group_id_part)

    print(f"Group Ids in extract_group_ids {group_ids[0]}")
    return group_ids


def create_new_report_name(account_id: str) -> str:
    """
    Creates an initial report name
    """
    timestr = time.strftime("%Y%m%d-%H%M%S")

    return account_id + timestr


def create_new_diff_name(account_id: str) -> str:
    """
    Creates an initial diff name
    """
    timestr = time.strftime("%Y%m%d-%H%M%S")

    return account_id + "_diff_" + timestr


def get_prowler_report_name() -> str:
    """
    Returns the name of the generated report
    """
    try:
        current_directory = os.getcwd()
        PROWLER_OUTPUT_LOCATION = "/var/task/platsec/compliance/lib/prowler/output"

        files = os.listdir(PROWLER_OUTPUT_LOCATION)
        if len(files) == 0:
            logger.error(f"No files {PROWLER_OUTPUT_LOCATION} {current_directory}")
            raise FileNotFoundError
        return files[0]
    except FileNotFoundError as ex:
        logger.error(f"Directory {PROWLER_OUTPUT_LOCATION} {current_directory}")
        raise ex


def create_workspace(workspace_location: str) -> bool:
    """
    Creates a temporary workspace
    """
    os.mkdir(workspace_location)
    return True


def delete_workspace(workspace_location: str) -> bool:
    """
    Deletes the temporary workspace
    """
    os.rmdir(workspace_location)
    return True


def format_default_groups(default_groups: list) -> list:
    """
    Formats the default groups
    to execute in prowler
    """
    formatted_groups = []
    for group in default_groups:
        formatted_group = group.rsplit("_")
        formatted_groups.append(formatted_group[1])

    return formatted_groups


def get_prowler_config():
    """
    Returns the prowler config
    for a Prowler run
    """
    return ProwlerConfig()


class ProwlerConfig:
    """
    Contains the config for
    Running prowler on MDTP Platform
    """

    def __init__(self):
        self.mode = os.environ.get("EXEC_MODE")
        self.bucket_name = os.environ.get("S3_BUCKET")
        self.group_location = os.environ.get("GROUP_LOCATION")
        self.default_groups = os.environ.get("DEFAULT_GROUPS")
        self.region = os.environ.get("DEFAULT_REGION")
        self.script_location = os.environ.get("SCRIPT_LOCATION")


class ProwlerExecutionRun:
    """
    Contains the metric data
    for a particular execution of
    Prowler
    """

    def __init__(self):
        self.new_report_name = None
        self.account_id = None
        self.group_ids = None