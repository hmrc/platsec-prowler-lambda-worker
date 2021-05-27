"""
Contains the  functions that will
process and produce the diff file for prowler
"""
import logging
import os
import time
import subprocess
import difflib
from typing import List, Dict

# Create a custom logger
logger = logging.getLogger("prowler")
c_handler = logging.StreamHandler()
c_format = logging.Formatter("%(name)s - %(levelname)s - %(message)s")
c_handler.setFormatter(c_format)
logger.addHandler(c_handler)


def extract_body(msg: str) -> str:
    """
    Extracts the body from the message
    """
    if msg == "" or msg is None:
        raise ValueError("SQS Message has no body element")
    else:
        msgBody = msg["Records"][0]["body"]
        return msgBody


def get_accountinfo(msg) -> str:
    """
    Returns a dictionary containing the
    account id and an array of prowler group checks.
    """
    if msg == "":
        raise IndexError
    else:
        try:
            account_id = msg[0]["Id"]
            return account_id
        except KeyError as err:
            raise KeyError
        except ValueError as err:
            raise err


def get_account_name(msg) -> str:
    """
    Returns the account name
    """
    try:
        account_name = msg[0]["Name"]
        return account_name
    except KeyError as err:
        raise err


def check_accounts(msg) -> int:
    """
    Returns the number of accounts to
    process.
    """
    accounts = 0

    if msg != "":
        accounts = len(msg["Records"][0]["body"])

    return accounts


def check_records(msg) -> int:
    """
    Returns the number of records
    sent in the SQS message
    """
    records = 0
    if msg is not None:
        records = len(msg["Records"])

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
    if len(groups) > 0:
        try:
            check_list = os.listdir(path)
            process_list = [group for group in groups if group in check_list]
            print(f" Process list {process_list}")
            if len(process_list) > 0:
                return process_list
            else:
                raise ValueError("No valid groups found")
        except FileNotFoundError as error:
            logger.error("File not found")
            raise error
    else:
        default_process_list = [default_group]
        return default_process_list


def execute_prowler(account_number: str, report_name: str, region: str, bucket_name: str, prowler_directory: str,
                    groups: List) -> bool:
    report_generated = False

    try:
        print(f"DEBUG *** {prowler_directory} creating attempt")

        print(f"DEBUG *** prowler_directory {prowler_directory}")
        os.chdir(prowler_directory)
        prowler_cmd = "./prowler"
        if len(groups) == 1:
            group_list = groups[0]
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
    except subprocess.CalledProcessError as error:
        logger.error(error)
    except FileNotFoundError as error:
        logger.error(error)
        report_generated = False
    except Exception as error:
        print(error)
        logger.error(f"{account_number} did not generate prowler report")
        report_generated = False
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


def get_groups(records_data: str, default_group: str) -> List:
    """
    Returns the specified groups in the
    SQS Message
    """
    try:
        if len(records_data[0]["Groups"]) > 0:
            return records_data[0]["Groups"]
        else:
            return [default_group]
    except IndexError as err:
        raise err


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
    try:
        os.mkdir(workspace_location)
        return True
    except Exception:
        return False


def delete_workspace(workspace_location: str) -> bool:
    """
    Deletes the temporary workspace
    """
    try:
        os.rmdir(workspace_location)
        return True
    except Exception:
        return False


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