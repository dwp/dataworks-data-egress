from data_egress import sqs_listener
import json
import pytest
from data_egress.sqs_listener import S3PrefixAndDynamoRecord


def test_process_message():
    json_file = open('/Users/udaykiranchokkam/DWP-Workspace/dataworks-aws-data-egress/python/tests/sqs_message.json')
    response = json.load(json_file)
    s3_prefixes = sqs_listener.process_messages(response)
    assert s3_prefixes[0] == 'data-egress-testing/2021-01-10/'


def test_process_message_with_error():
    json_file = open('/Users/udaykiranchokkam/DWP-Workspace/dataworks-aws-data-egress/python/tests/sqs_message_no_records.json')
    response = json.load(json_file)
    with pytest.raises(KeyError) as ex:
        sqs_listener.process_messages(response)
    assert str(ex.value) == '"Key: \'s3\' not found when retrieving the prefix from sqs message"'


def test_process_message_wrong_formatted_prefix_1():
    json_file = open('/Users/udaykiranchokkam/DWP-Workspace/dataworks-aws-data-egress/python/tests/sqs_message_wrong_formatted_prefix_1.json')
    response = json.load(json_file)
    s3_prefixes = sqs_listener.process_messages(response)
    assert len(s3_prefixes) == 0


def test_process_message_wrong_formatted_prefix_2():
    json_file = open('/Users/udaykiranchokkam/DWP-Workspace/dataworks-aws-data-egress/python/tests/sqs_message_wrong_formatted_prefix_2.json')
    response = json.load(json_file)
    s3_prefixes = sqs_listener.process_messages(response)
    assert len(s3_prefixes) == 0


def test_process_dynamo_db_response():
    records = [S3PrefixAndDynamoRecord("data-egress-testing/", [])]
    with pytest.raises(Exception) as ex:
        sqs_listener.process_dynamo_db_response(records)
    assert str(ex.value) == "No records found in dynamo db for the s3_prefix data-egress-testing/"


def test_process_dynamo_db_response_1():
    records = [S3PrefixAndDynamoRecord("data-egress-testing/", [{'source_bucket': '123'}, {'source_bucket': '456'}])]
    with pytest.raises(Exception) as ex:
        sqs_listener.process_dynamo_db_response(records)
    assert str(ex.value) == "More than 1 record for the s3_prefix data-egress-testing/"


def test_process_dynamo_db_response_2():
    records = [S3PrefixAndDynamoRecord("data-egress-testing/", [{'destination_bucket': '123'}])]
    with pytest.raises(KeyError) as ex:
        sqs_listener.process_dynamo_db_response(records)
    assert str(ex.value) == '"Key: \'source_bucket\' not found when retrieving from dynamodb response"'


def test_decrypt():
    plaintext_key = "1234=="




