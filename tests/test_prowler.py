"""
Tests for the MDTP Prowler Implementation
"""
import json
import os
import pytest
from datetime import datetime
from botocore.client import BaseClient  # type: ignore
from botocore.exceptions import ClientError
from src.platsec.compliance.prowler_exceptions import (
    AwsBucketPathCreateException,
    AwsProwlerFileException,
    AwsBotoAuthException)

from src.platsec.compliance.prowler_aws import (
    boto3_auth,
    setup_s3_client,
    setup_sqs_client,
    get_previous_report,
    copy_report,
    check_output_folder,
    setup_s3_client_lambda,
    create_output_folder,
    download_report,
    get_filenames,
    get_file_contents,
    save_diff,
    delete_old_files,
    check_diff_required
)

from src.platsec.compliance.prowler import (
    check_records,
    create_new_report_name,
    create_new_diff_name,
    get_account_name,
    validate_groups,
    get_accountinfo,
    check_accounts,
    execute_prowler,
    check_platsec_group,
    create_diff,
    get_groups,
    get_prowler_report_name,
    create_workspace,
    delete_workspace,
    extract_body,
    get_prowler_config,
    get_group_ids,
    extract_group_ids,
    format_default_groups,
    ProwlerExecutionRun,
    ProwlerConfig
)

from src.platsec.compliance.prowler_filters import (
    remove_escapes,
    pretty_print
)

from src.platsec.compliance.prowler_pipeline import (
  run_prowler,
  get_config,
  execute_aws_validation,
  create_aws_environment,
  execute_save_diff,
  get_aws_client,
  execute_filters,
  execute_clean_up,
  execute_diff_generation
)

from unittest.mock import Mock, patch


@pytest.mark.validation
def test_get_config_returns_valid() -> None:
    test_config = get_prowler_config()
    assert test_config is not None


@pytest.mark.validation
def test_get_single_group_contents(tmpdir):
    """
    Tests returning a group
    """

    group_filenames = ['group1_iam']
    group1_iam_file = tmpdir.join('group1_iam.sh')
    group1_iam_file.write('GROUP_ID[1]="group1"')

    prowler_group = get_group_ids(tmpdir, group_filenames)

    assert len(prowler_group) > 0


@pytest.mark.validation
def test_get_single_group_full_contents(tmpdir):
    """
    Tests returning a group
    """

    group_filenames = ['group1_iam']
    group1_iam_file = tmpdir.join('group1_iam.sh')
    group1_iam_file.write('GROUP_ID[1]="group1" GROUP_NUMBER[1]="1.0" GROUP_TITLE[1]="IAManagement - CIS only - [group1] ***********" GROUP_RUN_BY_DEFAULT[1]="Y" # run it when execute_all is called GROUP_CHECKS[1]="check11,check12"')

    prowler_group = get_group_ids(tmpdir, group_filenames)

    assert len(prowler_group) > 0


@pytest.mark.validation
def test_extract_group_id_single_group():
    """
    Tests group extraction
    """
    groups = [['GROUP_ID[1]="group1" GROUP_NUMBER[1]="1.0" GROUP_TITLE[1]="IAManagement - CIS only - [group1] ***********" GROUP_RUN_BY_DEFAULT[1]="Y" # run it when execute_all is called GROUP_CHECKS[1]="check11,check12"']]
    group_ids = extract_group_ids(groups)

    assert len(group_ids) == 1


@pytest.mark.validation
def test_extract_group_id_multiple_group():
    """
    Tests group extraction
    """
    groups = [['GROUP_ID[1]="group1" GROUP_NUMBER[1]="1.0" GROUP_TITLE[1]="IAManagement - CIS only - [group1] ***********" GROUP_RUN_BY_DEFAULT[1]="Y" # run it when execute_all is called GROUP_CHECKS[1]="check11,check12"'],
              ['GROUP_ID[2]="group2" GROUP_NUMBER[2]="2.0" GROUP_TITLE[2]="EC2Management - CIS only - [group2] ***********" GROUP_RUN_BY_DEFAULT[1]="Y" # run it when execute_all is called GROUP_CHECKS[1]="check11,check12"']]

    group_ids = extract_group_ids(groups)

    assert len(group_ids) == 2


@pytest.mark.validation
def test_get_no_group_contents(tmpdir):
    """
    Tests returning a group
    """

    group_filenames = ['group1_iam']
    prowler_group = get_group_ids(tmpdir, group_filenames)

    assert len(prowler_group) == 0


@pytest.mark.validation
def test_get_multiple_group_contents(tmpdir):
    """
    Tests returning a group
    """

    group_filenames = ['group1_iam', 'group20_platsec', 'group2_ec2']
    group1_iam_file = tmpdir.join('group1_iam.sh')
    group20_platsec_file = tmpdir.join('group20_platsec.sh')
    group2_ec2_file = tmpdir.join('group2_ec2.sh')

    group1_iam_file.write('GROUP_ID[1]="group1"')
    group20_platsec_file.write('GROUP_ID[20]="platsec"')
    group2_ec2_file.write('GROUP_ID[2]="ec2"')

    prowler_group = get_group_ids(tmpdir, group_filenames)

    assert len(prowler_group) == 3


@pytest.mark.validation
def test_get_account_info_valid_msg() -> None:
    """
    Tests that a valid name can be returned
    """
    data = get_valid_test_sqs_message()
    expected = "xxxx"

    actual = get_account_name(data)
    assert actual == expected


@pytest.mark.validation
def test_get_account_info_missing_name_returns_key_error() -> None:
    """
    Tests that a missing name raises a key error
    """
    data ={"Id": "806352241843", "Groups": []}
    with pytest.raises(KeyError):
        get_account_name(data)


@pytest.mark.validation
def test_message_body_extraction_errors_on_missing_message() -> None:
    """
    Test that the extraction routine raises a value error
    on a missing message body from the SQS queue.
    """

    record = ""

    with pytest.raises(ValueError):
        extract_body(record)


@pytest.mark.validation
def test_accounts_check() -> None:
    """
    Tests that we can check for accounts
    being in the message body.:w

    """
    json_data = get_valid_test_sqs_message()
    accounts = check_accounts(json_data)

    assert accounts > 0


@pytest.mark.validation
def test_accounts_check_returns_zero() -> None:
    """
    Tests that we can check for accounts
    being in the message body.

    """
    json_data = ""
    accounts = check_accounts(json_data)

    assert accounts == 0


@pytest.mark.core
@pytest.mark.aws
def test_get_last_output_file() -> None:
    """
    Tests that we can retrieve a file
    from the s3 bucket
    """
    s3_bucket_name = "test_bucket"
    account_name = "test_account"
    file_name = "test_file"
    test_file_content = "test_content"
    key = f"{account_name}/{file_name}"

    s3_client = Mock(get_object=Mock(return_value=test_file_content))

    file_contents = get_previous_report(s3_bucket_name, key, s3_client)

    s3_client.get_object.assert_called_once_with(Bucket=s3_bucket_name, Key=key)

    assert file_contents is not None


@pytest.mark.validation
def test_get_accounts() -> None:
    """
    Tests that an error is raised if there are no
    accounts to process.
    """
    json_data = get_valid_test_sqs_message()
    account = get_accountinfo(json_data)

    assert isinstance(account, str)


@pytest.mark.validation
def test_get_accounts_returns_IndexError() -> None:
    """
    Tests that an error is raised if there are no
    accounts to process.
    """
    records = ""

    with pytest.raises(IndexError):
        get_accountinfo(records)


@pytest.mark.validation
def test_get_accounts_returns_KeyError() -> None:
    """
    Tests that an error is raised if there is no
    Id key in message.
    """

    json_data = {"Name": "xxxx", "Groups": []}

    with pytest.raises(KeyError):
        get_accountinfo(json_data)


@pytest.mark.validation
def test_validate_groups() -> None:
    """
    Checks to see that the groups in the
    SQS Message exist in the prowler folder
    under the lib folder.
    """
    test_record = {"Id": "121212", "Name": "account-one", "Groups": ["group8_forensics", "group9_gdpr"]}
    groups = test_record["Groups"]
    default_group = "platsec20"
    path = os.path.join(os.getenv("HOME"), "Development/PythonProwlerImplementation",
                        "src/platsec/compliance/lib/prowler/groups")

    groups_validity = validate_groups(groups, path, default_group)

    assert len(groups_validity) > 0


@pytest.mark.validation
def test_validate_groups_returns_default_group() -> None:
    """
    Tests that we get the default group to run when
    there are no other groups to run
    """
    test_record = {"Id": "121212", "Name": "account-one", "Groups": ["group8_forensics", "group9_gdpr"]}
    groups = {}
    default_group = "platsec20"
    path = os.path.join(os.getenv("HOME"), "Development/PythonProwlerImplementation",
                        "src/platsec/compliance/lib/prowler/groups")

    groups_validity = validate_groups(groups, path, default_group)

    assert len(groups_validity) > 0


@pytest.mark.validation
def test_validate_groups_return_valueerror() -> None:
    """
    Checks to see if the validate groups
    returns a ValueError
    """
    test_record = {"Id": "121212", "Name": "account-one", "Groups": ["false_group"]}
    groups = test_record["Groups"]
    default_group = "platsec20"
    path = os.path.join(os.getenv("HOME"), "Development/PythonProwlerImplementation",
                        "src/platsec/compliance/lib/prowler/groups")

    with pytest.raises(ValueError):
        validate_groups(groups, path, default_group)


@pytest.mark.validation
def test_validate_groups_return_filenotfounderror() -> None:
    """
    Checks to see if the validate groups
    returns a ValueError
    """
    test_record = {"Id": "121212", "Name": "account-one", "Groups": ["false_group"]}
    groups = test_record["Groups"]
    default_group = "platsec20"
    path = os.path.join(os.getenv("HOME"), "Development/PythonProwlerImplement")

    with pytest.raises(FileNotFoundError):
        validate_groups(groups, path, default_group)


@pytest.mark.validation
def test_validate_groups_return_error() -> None:
    """
    Checks to see if the validate groups
    returns a ValueError
    """
    groups = None
    account_name = "account-one"
    path = os.path.join(os.getenv("HOME"), "Development/PythonProwlerImplementation",
                        "src/platsec/compliance/lib/prowler/groups")

    with pytest.raises(Exception):
        validate_groups(account_name, groups, path)


@pytest.mark.aws
def test_boto3_authentication_returns_exception() -> None:
    """
    Tests that authentication returns an exception
    """
    s3_client = Mock(assume_role=Mock(side_effect=get_client_error("AssumeRole", "AccessDenied", "S3")))
    mfa = "273941"
    username = "test.user"
    role = "testRole"
    account = "testAccount"
    aws_sts_endpoint = "https://sts.eu-west-2.amazonaws.com"

    with pytest.raises(AwsBotoAuthException):
        boto3_auth(mfa=mfa, username=username, role=role, account=account,
                   aws_sts_endpoint=aws_sts_endpoint)


@pytest.mark.aws
def test_boto3_authentication_returns_base_client() -> None:
    expected_mfa_credentials = {
        "Credentials": {
            "AccessKeyId": "testAccessKey",
            "SecretAccessKey": "testSecretAccessKey",
            "SessionToken": "testSessionToken"
        }
    }

    mock_sts_client = Mock(assume_role=Mock(return_value=expected_mfa_credentials))

    mfa = "273941"
    username = "test.user"
    role = "testRole"
    account = "testAccount"
    aws_sts_endpoint = "https://sts.eu-west-2.amazonaws.com"

    with patch("boto3.client", Mock(return_value=mock_sts_client)) as mock_boto_client:
        actual_mfa_credentials = boto3_auth(mfa=mfa, username=username, role=role, account=account,
                                            aws_sts_endpoint=aws_sts_endpoint)
        mock_boto_client.assert_called_once_with(service_name="sts", endpoint_url=aws_sts_endpoint)


@pytest.mark.aws
def test_sqs_client():
    expected_mfa_credentials = {
        "Credentials": {
            "AccessKeyId": "testAccessKey",
            "SecretAccessKey": "testSecretAccessKey",
            "SessionToken": "testSessionToken"
        }
    }

    aws_sqs_endpoint = "https://sqs.eu-west-2.amazonaws.com"
    mock_boto3 = Mock()
    mock_boto3.return_value = Mock(spec=BaseClient)

    with patch("boto3.client", mock_boto3):
        returned_client = setup_sqs_client(expected_mfa_credentials, aws_sqs_endpoint)

    assert isinstance(returned_client, BaseClient)

    mock_boto3.assert_called_once_with(service_name='sqs',
                                       aws_access_key_id=expected_mfa_credentials["Credentials"]["AccessKeyId"],
                                       aws_secret_access_key=expected_mfa_credentials["Credentials"]["SecretAccessKey"],
                                       aws_session_token=expected_mfa_credentials["Credentials"]["SessionToken"],
                                       endpoint_url=aws_sqs_endpoint
                                       )


@pytest.mark.aws
def test_s3_get_client_lambda() -> None:
    mock_boto3 = Mock()
    mock_boto3.return_value = Mock(spec=BaseClient)

    with patch("boto3.client", mock_boto3):
        returned_client = setup_s3_client_lambda()

    mock_boto3.assert_called_once()
    assert isinstance(returned_client, BaseClient)


@pytest.mark.aws
def test_s3_client():
    expected_mfa_credentials = {
        "Credentials": {
            "AccessKeyId": "testAccessKey",
            "SecretAccessKey": "testSecretAccessKey",
            "SessionToken": "testSessionToken"
        }
    }

    aws_s3_endpoint = "https://s3.eu-west-2.amazonaws.com"
    mock_boto3 = Mock()
    mock_boto3.return_value = Mock(spec=BaseClient)

    with patch("boto3.client", mock_boto3):
        returned_client = setup_s3_client(expected_mfa_credentials, aws_s3_endpoint)

    assert isinstance(returned_client, BaseClient)

    mock_boto3.assert_called_once_with(service_name='s3',
                                       aws_access_key_id=expected_mfa_credentials["Credentials"]["AccessKeyId"],
                                       aws_secret_access_key=expected_mfa_credentials["Credentials"]["SecretAccessKey"],
                                       aws_session_token=expected_mfa_credentials["Credentials"]["SessionToken"],
                                       endpoint_url=aws_s3_endpoint
                                       )


@pytest.mark.validation
def test_validate_groups_with_valid_and_invalid_groups() -> None:
    """
    Checks to see that the specified and groups are valid
    and should only return the valid groups omitting the
    invalid groups
    """
    test_record = {"Id": "121212", "Name": "account-one",
                   "Groups": ["invalid_group", "group8_forensics", "group9_gdpr"]}
    groups = test_record["Groups"]
    default_group = "platsec20"

    path = os.path.join(os.getenv("HOME"), "Development/PythonProwlerImplementation",
                        "src/platsec/compliance/lib/prowler/groups")

    groups_validity = validate_groups(groups, path, default_group)

    assert len(groups_validity) == 2


@pytest.mark.validation
def test_ensure_platsec_group_present() -> None:
    """
    Checks to see that the mandatory
    Platsec Group (20) is in the
    Config file passed from SQS
    """
    test_config = {"Id": "121212", "Name": "account-one",
                   "Groups": ["group20_platsec", "group8_forensics", "group9_gdpr"]}
    platsec_group = "group20_platsec"

    group_present = check_platsec_group(test_config, platsec_group)

    assert group_present


@pytest.mark.validation
def test_ensure_platsec_group_not_present() -> None:
    """
    Checks to see that the mandatory
    Platsec Group (20) is in the
    Config file passed from SQS
    """
    test_config = {"Id": "121212", "Name": "account-one",
                   "Groups": ["group8_forensics", "group9_gdpr"]}
    platsec_group = "group20_platsec"

    group_present = check_platsec_group(test_config, platsec_group)

    assert not group_present


@pytest.mark.aws
def test_check_s3_output_folder_for_account_exists(mocker) -> None:
    """
    Check that there is an output storage location
    for the account id.
    """
    test_account = "test_account"
    test_bucket = "test_bucket"
    expected_response = {
        'IsTruncated': True,
        'Marker': 'string',
        'NextMarker': 'string',
        'ResponseMetadata': {
            'Contents': [
                {
                    'Key': 'string',
                    'LastModified': datetime(2015, 1, 1),
                    'ETag': 'string',
                    'Size': 123,
                    'StorageClass': 'STANDARD',
                    'Owner': {
                        'DisplayName': 'string',
                        'ID': 'string'
                    }
                },
            ]},
        'Name': 'string',
        'Prefix': 'string',
        'Delimiter': 'string',
        'MaxKeys': 123,
        'CommonPrefixes': [
            {
                'Prefix': 'string'
            },
        ],
        'EncodingType': 'url'
    }
    s3_client = Mock(list_objects_v2=Mock(return_value=expected_response))

    actual_response = check_output_folder(test_bucket, test_account, s3_client)
    s3_client.list_objects_v2.assert_called_once_with(Bucket=test_bucket, Delimiter='\\', Prefix=test_account)

    assert actual_response


@pytest.mark.aws
def test_check_s3_output_folder_returns_client_error(mocker) -> None:
    """
    Check that a client exception error is returned
    """
    test_account = "test_account"
    test_bucket = "test_bucket"
    s3_client = Mock(list_objects_v2=Mock(side_effect=get_client_error("AssumeRole", "AccessDenied", "S3")))

    with pytest.raises(AwsBucketPathCreateException):
        check_output_folder(test_bucket, test_account, s3_client)


@pytest.mark.validation
@pytest.mark.aws
def test_check_s3_output_folder_for_account_doesnt_exist(mocker) -> None:
    """
    Check that there is an output storage location
    for the account id.
    """
    test_account = "test_account"
    test_bucket = "test_bucket"
    expected_response = {
        'IsTruncated': True,
        'ResponseMetadata': {
        },
        'Name': 'string',
        'Prefix': 'string',
        'Delimiter': 'string',
        'MaxKeys': 123,
        'CommonPrefixes': [
            {
                'Prefix': 'string'
            },
        ],
        'EncodingType': 'url',
        'KeyCount': 123,
        'ContinuationToken': 'string',
        'NextContinuationToken': 'string',
        'StartAfter': 'string'
    }
    s3_client = Mock(list_objects_v2=Mock(return_value=expected_response))

    actual_response = check_output_folder(test_bucket, test_account, s3_client)
    s3_client.list_objects_v2.assert_called_once_with(Bucket=test_bucket, Delimiter='\\', Prefix=test_account)

    assert not actual_response


@pytest.mark.core
def test_execute_prowler(tmpdir) -> None:
    """
    Tests the execution of prowler
    """
    account_number = "1233434334"
    role = "test_role"
    bucket_name = "test_bucket"
    region = "eu-west-2"
    group = ["group20_platsec"]
    prowler_directory = tmpdir.mkdir('prowler_dir')
    prowler_file = prowler_directory.join('prowler')
    prowler_file.write('#!/bin/bash echo "Hello World"')
    prowler_file.chmod(744)

    with patch('subprocess.run') as mock_prowler:
        mock_prowler.return_value = True
        report_result = execute_prowler(account_number, role, region,
                                        bucket_name, prowler_directory, group)
        mock_prowler.assert_called_once()

    assert report_result


@pytest.mark.core
def test_execute_prowler_with_multiple_groups(tmpdir) -> None:
    """
    Tests the execution of prowler
    """
    account_number = "1233434334"
    role = "test_role"
    bucket_name = "test_bucket"
    region = "eu-west-2"
    group = ["group20_platsec", "group23", "group_35"]
    prowler_directory = tmpdir.mkdir('prowler_dir')
    prowler_file = prowler_directory.join('prowler')
    prowler_file.write('#!/bin/bash echo "Hello World"')
    prowler_file.chmod(744)

    with patch('subprocess.run') as mock_prowler:
        mock_prowler.return_value = True
        report_result = execute_prowler(account_number, role, region,
                                        bucket_name, prowler_directory, group)
        mock_prowler.assert_called_once()

    assert report_result


@pytest.mark.core
def test_execute_prowler_returns_false_on_exception(tmpdir) -> None:
    """
    Test that an exception is raised and caught
    """
    account_number = "1233434334"
    role = "test_role"
    bucket_name = "test_bucket"
    region = "eu-west-2"
    group = ["group20_platsec", "group23", "group_35"]
    prowler_directory = tmpdir.mkdir('prowler_dir')
    prowler_file = prowler_directory.join('prowler')
    prowler_file.write('#!/bin/bash echo "Hello World"')
    prowler_file.chmod(744)
    with patch('subprocess.run') as mock_prowler:
        mock_prowler.side_effect = Exception
        report_result = execute_prowler(account_number, role, region,
                                        bucket_name, prowler_directory, group)

    assert report_result is False


@pytest.mark.core
def test_execute_diff_raises_exception() -> None:
    """
    Test that diff execution generates
    an exception
    """
    original_report = "test_file_1"
    generated_report = "test_file_2"
    expected_diff_output = "diff1,diff3"

    with patch('difflib.unified_diff') as mock_difflib:
        mock_difflib.side_effect = Exception
        with pytest.raises(Exception):
            create_diff(original_report, generated_report)
            mock_difflib.assert_called_once()


@pytest.mark.validation
def test_get_groups_returns_keyerror() -> None:
    records_data = {"Id": "806352241843", "Name": "xxxx"}
    default_group = ""
    with pytest.raises(KeyError):
        get_groups(records_data, default_group)


@pytest.mark.core
def test_format_default_groups() -> None:
    default_groups = ["group20_platsec"]
    actual = format_default_groups(default_groups)

    assert len(actual) == 1


@pytest.mark.validation
def test_get_groups_returns_default_group() -> None:
    """
    Tests that the default group is returned
    When no groups are sepcified
    """
    records_data = get_valid_test_sqs_message()
    default_group = "group20_platsec"

    groups = get_groups(records_data, default_group)
    assert len(groups) == 1
    assert groups[0] == default_group

@pytest.mark.core
def test_execute_diff_succeeds() -> None:
    """
    Test that diff execution works
    """
    original_report = "test_file_1"
    generated_report = "test_file_2"
    expected_diff_output = "diff1,diff3"

    with patch('difflib.unified_diff') as mock_difflib:
        mock_difflib.return_value = expected_diff_output
        generated_diff_output = create_diff(original_report, generated_report)
        mock_difflib.assert_called_once()

    assert generated_diff_output is not None


@pytest.mark.core
@patch('src.platsec.compliance.prowler_pipeline.execute_prowler', return_value=True)
def test_run_prowler_succeeds(mock_execute_prowler) -> None:
    """
    Tests that the call to run prowler
    returns true
    """
    account_number = "12345783748"
    report_name = "test_report"
    region = "eu-west-1"
    bucket_name = "test_bucket"
    prowler_directory = "/test_directory"
    groups = ["test_group_1"]
    #mock_execute_prowler.return_value = True

    assert run_prowler(account_number, report_name,
                       region, bucket_name,
                       prowler_directory, groups)

@pytest.mark.core
@patch('src.platsec.compliance.prowler_pipeline.get_prowler_config')
def test_get_config(mock_get_config) -> None:
    """
    Tests that the pipeline returns
    A configuration class
    """
    mock_get_config.return_value = ProwlerConfig()
    assert get_config()


@pytest.mark.core
@patch('src.platsec.compliance.prowler_pipeline.check_output_folder', return_value=True)
def test_execute_aws_validation(mock_execute_aws_validation) -> None:
    """
    Tests that execution_aws_validation
    returns a boolean
    """
    bucket_name = "TestBucket"
    account_id = "123456789"
    assert execute_aws_validation(bucket_name, account_id, BaseClient)


@pytest.mark.core
@patch('src.platsec.compliance.prowler_pipeline.create_output_folder', return_value=True)
def test_create_aws_environment(mock_create_aws_environment) -> None:
    """
    Tests that the create_aws_environment
    returns a boolean
    """
    bucket_name = "TestBucket"
    account_id = "123456789"
    assert create_aws_environment(bucket_name,account_id,BaseClient)


@pytest.mark.core
@patch('src.platsec.compliance.prowler_pipeline.save_diff')
def test_execute_save_diff(mock_execute_save_diff) -> None:
    """
    Tests that execute_save_diff returns
    a filename
    """
    bucket_name = "TestBucket"
    account_id = "123456789"
    filtered_diff_data = "djsljfssgsgs"

    mock_execute_save_diff.return_value = "TestFile"
    assert execute_save_diff(filtered_diff_data, bucket_name, account_id, BaseClient)


@pytest.mark.core
@patch('src.platsec.compliance.prowler_pipeline.setup_s3_client_lambda',
       return_value=BaseClient)
def test_get_aws_client(mock_get_aws_client) -> None:
    """
    Test that a baseclient is returned
    """
    assert get_aws_client()


@pytest.mark.core
def test_execute_filters() -> None:
    """
    Tests that we can execute a filter list
    """
    diff_data = "fasdfs\n"
    filter_list = [remove_escapes]

    actual = execute_filters(diff_data, filter_list)
    assert len(actual) > 0


@pytest.mark.core
@patch('src.platsec.compliance.prowler_pipeline.get_sorted_file_list')
def test_execute_clean_up(mock_exectute_cleanup) -> None:
    """
    Tests that we can clean up
    the file system environment
    """
    bucket_name="TestBucket"
    mock_exectute_cleanup.return_value = ["test.txt"]
    files = execute_clean_up(bucket_name, BaseClient)
    assert files is False


@pytest.mark.core
@patch('src.platsec.compliance.prowler_pipeline.get_sorted_file_list')
@patch('src.platsec.compliance.prowler_pipeline.delete_old_files')
def test_execute_clean_up_multiple_files(mock_execute_cleanup, mock_delete_old_files) -> None:
    """
    Tests that we can clean up
    the file system environment
    """
    bucket_name="TestBucket"
    files_list = mock_execute_cleanup.return_value = ["test.txt", "ert.dh", "tryr.sh", "ert.sh"]
    mock_delete_old_files.return_value = "test"

    files = execute_clean_up(bucket_name, BaseClient)

    assert files is True


@pytest.mark.core
@patch('src.platsec.compliance.prowler_pipeline.get_filenames', return_value=["test.txt"])
def test_execute_diff_generation(mock_execute_diff_generation) -> None:
    bucket_name = "testBucket"
    account_id = "123456789"
    result = execute_diff_generation(bucket_name, account_id, BaseClient)
    assert result == ''


@pytest.mark.aws
def test_copy_report_to_s3() -> None:
    """
    Tests the copying of the report
    to an s3 bucket
    """
    file_name = "test_file"
    s3_bucket_name = "test_bucket"
    account_name = "12345666757"
    response = True
    s3_client = Mock(upload_file=Mock(return_value=response))

    actual_response = copy_report(file_name, account_name, s3_bucket_name, s3_client)
    s3_client.upload_file.assert_called_once_with(File=file_name, Bucket=s3_bucket_name, Prefix=account_name)

    assert actual_response


@pytest.mark.core
def test_get_groups_from_sqs_record() -> None:
    """
    Tests the extraction of the groups
    from the SQS Record
    """
    json_data = get_valid_test_sqs_message()
    default_group = "group20_platsec"
    groups = get_groups(json_data, default_group)

    assert len(groups) > 0


@pytest.mark.validation
@pytest.mark.aws
def test_create_missing_s3_output_folder() -> None:
    """
    Test the creation of the output folder
    in S3 if it is not present.
    """
    test_account = "123458648945"
    test_bucket = "test_bucket"
    mock_response = {
        'Expiration': 'string',
        'ETag': 'string',
        'ServerSideEncryption': 'AES256',
        'VersionId': 'string',
        'SSECustomerAlgorithm': 'string',
        'SSECustomerKeyMD5': 'string',
        'SSEKMSKeyId': 'string',
        'SSEKMSEncryptionContext': 'string',
        'BucketKeyEnabled': True,
        'RequestCharged': 'requester'
    }
    s3_lambda_client = Mock(put_object=Mock(return_value=mock_response))

    actual_response = create_output_folder(test_bucket, test_account, s3_lambda_client)
    s3_lambda_client.put_object.assert_called_once_with(Bucket=test_bucket, Key=test_account + '/')

    assert actual_response is not None


@pytest.mark.core
def test_get_generated_report() -> None:
    """
    Checks and returns the generated report name
    because the output folder is cleared down after every run
    we can just return whats there
    """


@pytest.mark.core
def test_get_prowler_report_name() -> None:
    """
    Tests that we can retrieve the prowler
    report name
    """
    test_file = "prowler-output--2329102333113.csv"

    with patch('os.listdir') as mock_os_listdir:
        mock_os_listdir.return_value = [test_file]
        file_name = get_prowler_report_name()
        mock_os_listdir.assert_called_once()

    assert file_name == test_file


@pytest.mark.core
def test_create_temp_workspace() -> None:
    """
    Test that we can create a temp
    workspace
    """
    workspace_location = "/test/location/workspace"

    with patch('os.mkdir') as mock_os_createdir:
        mock_os_createdir.return_value = True
        actual_outcome = create_workspace(workspace_location)
        mock_os_createdir.assert_called_once()

    assert actual_outcome


@pytest.mark.core
def test_delete_temp_workspace() -> None:
    """
    Tests that we delete the workspace
    """
    workspace_location = "/test/location/workspace"
    with patch('os.rmdir') as mock_os_removedir:
        mock_os_removedir.return_value = True
        actual_outcome = delete_workspace(workspace_location)
        mock_os_removedir.assert_called_once()

    assert actual_outcome


@pytest.mark.core
def test_get_previous_report() -> None:
    """
    Test that we can open the previous report
    """
    test_bucket = "test_bucket"
    test_account = "123454344"


@pytest.mark.aws
def test_download_report_to_workspace() -> None:
    """
    Test that we can download the report from S3
    into the temporary workspace to be able to
    perform a diff on it.
    """
    test_location = "./lib/prowler/workspacce"
    test_bucket = "test_bucket"
    test_file = "test_file.csv"
    s3_lambda_client = Mock(put_object=Mock(return_value=""))

    actual_response = download_report(test_bucket, s3_lambda_client, test_file, test_location)
    s3_lambda_client.download_file.assert_called_once_with(Bucket=test_bucket, FileName=test_file,
                                                           Location=test_location)

    assert actual_response is not None
    assert actual_response


@pytest.mark.aws
def test_get_filename_returns_AwsProwlerFileException() -> None:
    """
    Test that AWSProwlerFileException is
    returned on ClientError
    """
    s3_client = Mock(list_objects_v2=Mock(side_effect=get_client_error("AssumeRole", "AccessDenied", "S3")))
    bucket_name = "TestBucket"
    test_account = "1232131323"

    with pytest.raises(AwsProwlerFileException):
        reports = get_filenames(bucket_name, test_account, s3_client)


@pytest.mark.aws
def test_get_filenames_two_files_existing() -> None:
    """
    Tests that we can retrieve filenames
    from the s3 bucket
    """
    data = {
        "Contents": [
            {
                "Key": "480830536305/",
                "LastModified": "2021-02-11T13:21:19+00:00",
                "ETag": "\"d41d8cd98f00b204e9800998ecf8427e\"",
                "Size": 0,
                "StorageClass": "STANDARD"
            },
            {
                "Key": "480830536305/48083053630520210211-131944.txt",
                "LastModified": "2021-02-11T13:21:19+00:00",
                "ETag": "\"6cec99c28b772700027e3ea4d6c14743\"",
                "Size": 8503,
                "StorageClass": "STANDARD"
            },
            {
                "Key": "480830536305/48083053630520210211-567944.txt",
                "LastModified": "2021-02-11T13:21:19+00:00",
                "ETag": "\"6cec99c28b772700027e3ea4d6c14743\"",
                "Size": 8503,
                "StorageClass": "STANDARD"
            }
        ]
    }

    test_data = data
    test_account = '480830536305'
    bucket_name = "test_bucket"
    s3_client_mock = Mock(spec=BaseClient, list_objects_v2=Mock(return_value=test_data))

    files = get_filenames(bucket_name, test_account, s3_client_mock)

    assert files is not None
    assert len(files) == 2


@pytest.mark.aws
def test_get_filenames_empty_reponse_returns_none() -> None:
    """
    Tests that we return an empty response
    from the s3 bucket
    """
    data = {
    }

    test_data = data
    test_account = '480830536305'
    bucket_name = "test_bucket"
    s3_client_mock = Mock(spec=BaseClient, list_objects_v2=Mock(return_value=test_data))

    files = get_filenames(bucket_name, test_account, s3_client_mock)

    assert files is None


@pytest.mark.aws
def test_get_file_contents() -> None:
    """
    Tests that we can read the contents of a file
    stored on S3 so that we can perform a difference
    on it.
    """
    bucket_name = "test_bucket"
    test_account_id = "23428048223432"
    test_file_name = "testfile.txt"
    test_data = "This is test data"

    s3_client_mock = Mock(spec=BaseClient,
                          get_object=Mock(return_value={'Body': Mock(read=Mock(return_value=test_data))}))

    actual_data = get_file_contents(bucket_name, test_account_id, test_file_name, s3_client_mock)

    assert actual_data == "This is test data"


@pytest.mark.aws
def test_save_diff_to_s3() -> None:
    """
    Tests that we can safe the difference file to s3
    """
    bucket_name = "test_bucket"
    test_account_id = "12345678454"
    test_diff_file_name = "diff1.txt"
    diff_data = "sdjflsfjls"

    data = {
        "Expiration": "string",
        "ETag": "string",
        "ServerSideEncryption": "AES256",
        "VersionId": "string",
        "SSECustomerAlgorithm": "string",
        "SSECustomerKeyMD5": "string",
        "SSEKMSKeyId": "string",
        "SSEKMSEncryptionContext": "string",
        "BucketKeyEnabled": "true",
        "RequestCharged": "requester"
    }

    s3_client_mock = Mock(spec=BaseClient, put_object=Mock(return_value=data))
    actual_response = save_diff(bucket_name, test_account_id, test_diff_file_name,
                                diff_data, s3_client_mock)

    assert actual_response == data


@pytest.mark.aws
def test_delete_old_files_returns_exception() -> None:
    """
    Tests that deleting files returns
    an exception
    """
    test_file = "filefolderpath/1.txt"
    bucket_name = "test_bucket"
    test_account_id = "1233443534234"
    s3_client = Mock(delete_object=Mock(side_effect=get_client_error("AssumeRole", "AccessDenied", "S3")))

    with pytest.raises(AwsProwlerFileException):
        delete_old_files(bucket_name, test_file, s3_client)


@pytest.mark.aws
def test_delete_old_files() -> None:
    """
    Test that the redundant files are removed
    at the beginning of each run
    """
    test_file = "filefolderpath/1.txt"
    bucket_name = "test_bucket"
    test_account_id = "1233443534234"

    data = {
        "ResponseMetadata": {
            "DeleteMarker": "true",
            "VersionId": "string",
            "RequestCharged": "requester"
        }
    }

    s3_client_mock = Mock(spec=BaseClient, delete_object=Mock(return_value=data))

    actual_response = delete_old_files(bucket_name, test_file, s3_client_mock)

    assert actual_response == data


@pytest.mark.core
def test_create_new_report_name() -> None:
    """
    Test that we can generate a report name
    """
    account_id = "123324922424"

    report_name = create_new_report_name(account_id)

    assert report_name is not None
    assert len(report_name) > 0


@pytest.mark.core
def test_create_new_diff_name() -> None:
    """
    Test that we can generate a diff name
    """
    account_id = "123324922424"

    report_name = create_new_diff_name(account_id)

    assert report_name is not None
    assert len(report_name) > 0


@pytest.mark.aws
def test_create_output_folder_return_exception() -> None:
    """
    Tests that an exception is returned
    """
    s3_client = Mock(put_object=Mock(side_effect=get_client_error("AssumeRole", "AccessDenied", "S3")))
    test_bucket = "test_bucket"
    test_account = "5043859053"

    with pytest.raises(AwsBucketPathCreateException):
        create_output_folder(test_bucket, test_account, s3_client)


@pytest.mark.aws
def test_check_diff_required_returns_true() -> None:
    """
    Tests that the difference check returns
    True
    """
    test_bucket = "TestBucket"
    account_id = "123456789"
    test_response = {
        'IsTruncated': "True",
        'Marker': 'string',
        'NextMarker': 'string',
        'Contents': [
            {
                'Key': 'string',
                'LastModified': datetime(2015, 1, 1),
                'ETag': 'string',
                'Size': 123,
                'StorageClass': 'STANDARD',
                'Owner': {
                    'DisplayName': 'string',
                    'ID': 'string'
                }
            },
            {
                'Key': 'string',
                'LastModified': datetime(2015, 1, 1),
                'ETag': 'string',
                'Size': 123,
                'StorageClass': 'STANDARD',
                'Owner': {
                    'DisplayName': 'string',
                    'ID': 'string'
                }
            },
            {
                'Key': 'string',
                'LastModified': datetime(2015, 1, 1),
                'ETag': 'string',
                'Size': 123,
                'StorageClass': 'STANDARD',
                'Owner': {
                    'DisplayName': 'string',
                    'ID': 'string'
                }
            },
            {
                'Key': 'string',
                'LastModified': datetime(2015, 1, 1),
                'ETag': 'string',
                'Size': 123,
                'StorageClass': 'STANDARD',
                'Owner': {
                    'DisplayName': 'string',
                    'ID': 'string'
                }
            },
        ],
        'Name': 'string',
        'Prefix': 'string',
        'Delimiter': 'string',
        'MaxKeys': 123,
        'CommonPrefixes': [
            {
                'Prefix': 'string'
            },
        ],
        'EncodingType': 'url'
    }

    s3_client: Mock = Mock(list_objects=Mock(return_value=test_response))

    response = check_diff_required(test_bucket, account_id, s3_client)

    assert response


@pytest.mark.aws
def test_check_diff_required_returns_false() -> None:
    """
    Tests that the difference check returns
    True
    """
    test_bucket = "TestBucket"
    account_id = "123456789"
    test_response = {
        'IsTruncated': "True",
        'Marker': 'string',
        'NextMarker': 'string',
        'Contents': [
            {
                'Key': 'string',
                'LastModified': datetime(2015, 1, 1),
                'ETag': 'string',
                'Size': 123,
                'StorageClass': 'STANDARD',
                'Owner': {
                    'DisplayName': 'string',
                    'ID': 'string'
                }
            },
        ],
        'Name': 'string',
        'Prefix': 'string',
        'Delimiter': 'string',
        'MaxKeys': 123,
        'CommonPrefixes': [
            {
                'Prefix': 'string'
            },
        ],
        'EncodingType': 'url'
    }

    s3_client: Mock = Mock(list_objects=Mock(return_value=test_response))

    response = check_diff_required(test_bucket, account_id, s3_client)

    assert not response


@pytest.mark.aws
def test_check_diff_required_returns_exception() -> None:
    """
    Tests that the difference check returns
    Exception
    """
    test_bucket = "TestBucket"
    account_id = "123456789"
    test_response = {
        'IsTruncated': "True",
        'Marker': 'string',
        'NextMarker': 'string',
        'Contents': [
            {
                'Key': 'string',
                'LastModified': datetime(2015, 1, 1),
                'ETag': 'string',
                'Size': 123,
                'StorageClass': 'STANDARD',
                'Owner': {
                    'DisplayName': 'string',
                    'ID': 'string'
                }
            },
        ],
        'Name': 'string',
        'Prefix': 'string',
        'Delimiter': 'string',
        'MaxKeys': 123,
        'CommonPrefixes': [
            {
                'Prefix': 'string'
            },
        ],
        'EncodingType': 'url'
    }

    s3_client = Mock(list_objects=Mock(side_effect=get_client_error("AssumeRole", "AccessDenied", "S3")))

    with pytest.raises(AwsProwlerFileException):
        check_diff_required(test_bucket, account_id, s3_client)


@pytest.mark.aws
def test_save_diff_returns_exception() -> None:
    """
    Test that the save diff returns an exception
    """
    bucket_name = "testBucket"
    account_id = "123243252352"
    file_name = "test_file"
    diff_data = "sdfjssdjsklgjsd"
    s3_client = Mock(put_object=Mock(side_effect=get_client_error("AssumeRole", "AccessDenied", "S3")))

    with pytest.raises(AwsProwlerFileException):
        save_diff(bucket_name, account_id, file_name, diff_data, s3_client)


@pytest.mark.validation
def test_remove_escapes_returns() -> None:
    """
    Tests that the remove escapes returns
    a string
    """
    msg = "test_message"
    result = remove_escapes(msg)
    assert len(result) > 0


@pytest.mark.validation
def test_pretty_print_returns() -> None:
    """
    Tests that the pretty print routing returns
    a string
    """
    msg = "test_message"
    result = pretty_print(msg)
    assert len(result) > 0


@pytest.mark.core
def test_formatted_groups_returns_valid_list() -> None:
    """
    Tests that we have the correct formatted list

    """


def get_valid_test_sqs_message() -> dict:
    """
    Simulates the JSON message being
    retrieved from SQS
    """
    data = {"Id": "806352241843", "Name": "xxxx", "Groups": []}
    return data


def get_client_error(operation: str, code: str, msg: str):
    return ClientError(
        operation_name=operation,
        error_response={
            "Error": {
                "Code": code,
                "Message": msg,
            }
        }
    )


def get_invalid_multi_records_sqs_message() -> dict:
    """
    Simulates SQS returning a message with
    multiple Record entries
    """
    data = {
        "Records": [
            {
                "messageId": "2e1424d4-f796-459a-8184-9c92662be6da",
                "receiptHandle": "AQEBzWwaftRI0KuVm4tP+/7q1rGgNqicHq...",
                "body": [
                    {"Id": "121212", "Name": "account-one", "Checks": [1, 2, 3]},
                    {"Id": "343434", "Name": "account-two", "Checks": [1, 2, 3]}
                ]
                ,
                "attributes": {
                    "ApproximateReceiveCount": "1",
                    "SentTimestamp": "1545082650636",
                    "SenderId": "AIDAIENQZJOLO23YVJ4VO",
                    "ApproximateFirstReceiveTimestamp": "1545082650649"
                },
                "messageAttributes": {},
                "md5OfBody": "e4e68fb7bd0e697a0ae8f1bb342846b3",
                "eventSource": "aws:sqs",
                "eventSourceARN": "arn:aws:sqs:us-east-2:123456789012:my-queue",
                "awsRegion": "us-east-2"
            },
            {
                "messageId": "2e1424d4-f796-459a-8184-9c92662be6da",
                "receiptHandle": "AQEBzWwaftRI0KuVm4tP+/7q1rGgNqicHq...",
                "body": [
                    {"Id": "121212", "Name": "account-one", "Checks": [1, 2, 3]},
                    {"Id": "343434", "Name": "account-two", "Checks": [1, 2, 3]}
                ]
                ,
                "attributes": {
                    "ApproximateReceiveCount": "1",
                    "SentTimestamp": "1545082650636",
                    "SenderId": "AIDAIENQZJOLO23YVJ4VO",
                    "ApproximateFirstReceiveTimestamp": "1545082650649"
                },
                "messageAttributes": {},
                "md5OfBody": "e4e68fb7bd0e697a0ae8f1bb342846b3",
                "eventSource": "aws:sqs",
                "eventSourceARN": "arn:aws:sqs:us-east-2:123456789012:my-queue",
                "awsRegion": "us-east-2"
            }
        ]
    }
    return data
