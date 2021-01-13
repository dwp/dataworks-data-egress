from data_egress import sqs_listener
import json
import pytest
from data_egress.sqs_listener import S3PrefixAndDynamoRecord
from moto import mock_s3, mock_dynamodb2, mock_sqs
import boto3
import argparse
import logging

AWS_REGION = "eu-west-2"
DYNAMODB_TABLENAME = "data-egress"
HASH_KEY = "pipeline_name"
RANGE_KEY = "source_prefix"

def test_process_message():
    json_file = open('/Users/udaykiranchokkam/DWP-Workspace/dataworks-data-egress/tests/sqs_message.json')
    message_body = json.load(json_file)
    response = {"Messages": [{"Body": json.dumps(message_body)}]}
    s3_prefixes = sqs_listener.process_messages(response["Messages"])
    assert s3_prefixes[0] == 'data-egress-testing/2021-01-10/'


def test_process_message_with_error():
    json_file = open('/Users/udaykiranchokkam/DWP-Workspace/dataworks-data-egress/tests/sqs_message_no_records.json')
    message_body = json.load(json_file)
    response = {"Messages": [{"Body": json.dumps(message_body)}]}
    with pytest.raises(KeyError) as ex:
        sqs_listener.process_messages(response["Messages"])
    assert str(ex.value) == '"Key: \'s3\' not found when retrieving the prefix from sqs message"'


def test_process_message_wrong_formatted_prefix_1():
    json_file = open('/Users/udaykiranchokkam/DWP-Workspace/dataworks-data-egress/tests/sqs_message_wrong_formatted_prefix_1.json')
    message_body = json.load(json_file)
    response = {"Messages": [{"Body": json.dumps(message_body)}]}
    s3_prefixes = sqs_listener.process_messages(response["Messages"])
    assert len(s3_prefixes) == 0


def test_process_message_wrong_formatted_prefix_2():
    json_file = open('/Users/udaykiranchokkam/DWP-Workspace/dataworks-data-egress/tests/sqs_message_wrong_formatted_prefix_2.json')
    message_body = json.load(json_file)
    response = {"Messages": [{"Body": json.dumps(message_body)}]}
    s3_prefixes = sqs_listener.process_messages(response["Messages"])
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

@mock_sqs
@mock_dynamodb2
def test_all(monkeypatch):
    sqs_client = boto3.client('sqs')
    json_file = open('/Users/udaykiranchokkam/DWP-Workspace/dataworks-data-egress/tests/sqs_message.json')
    response = json.load(json_file)
    msg_json_str = json.dumps(response)
    args = mock_args()
    args.sqs_url = mock_get_sqs_resource().url
    sqs_client.send_message(QueueUrl=args.sqs_url, MessageBody=msg_json_str)
    monkeypatch.setattr(sqs_listener, "get_dynamodb_resource", mock_get_dynamodb_resource)
    sqs_listener.listen(args)

@mock_sqs
def mock_get_sqs_resource():
    sqs = boto3.resource('sqs')
    test_sqs_queue = sqs.create_queue(QueueName='test-sqs-queue')
    return test_sqs_queue



@mock_dynamodb2
def mock_get_dynamodb_resource():
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
    table = dynamodb.create_table(
        TableName=DYNAMODB_TABLENAME,
        KeySchema=[
            {"AttributeName": HASH_KEY, "KeyType": "HASH"},  # Partition key
            {"AttributeName": RANGE_KEY, "KeyType": "RANGE"},  # Sort key
        ],
        AttributeDefinitions=[
            {"AttributeName": HASH_KEY, "AttributeType": "S"},
            {"AttributeName": RANGE_KEY, "AttributeType": "S"},
        ],
        ProvisionedThroughput={"ReadCapacityUnits": 10, "WriteCapacityUnits": 10},
    )
    table.put_item(Item={HASH_KEY: "OpsMI", RANGE_KEY: "data-egress-testing/2021-01-10/",
                         'source_bucket': "1234", 'destination_bucket': "1234", 'destination_prefix': "output/", 'transfer_type': "S3", 'recipient_name': "OpsMI"})
    return dynamodb

def mock_args():
    args = argparse.Namespace()
    args.log_level = logging.INFO
    return args








