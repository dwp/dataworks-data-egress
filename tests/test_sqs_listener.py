from data_egress import sqs_listener
import json
import pytest
from data_egress.sqs_listener import S3PrefixAndDynamoRecord
from moto import mock_s3, mock_dynamodb2, mock_sqs
import boto3
import argparse
import logging
import zlib

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter
import base64
import binascii

MOTO_SERVER_URL = "http://127.0.0.1:5000"
SOURCE_PREFIX = "data-egress-testing/2021-01-10/"
RECIPIENT_NAME = "OpsMI"
S3_TRANSFER_TYPE = "S3"
DESTINATION_BUCKET = "4321"
SOURCE_BUCKET = "1234"
DESTINATION_PREFIX = "output/"
AWS_REGION = "eu-west-2"
DYNAMODB_TABLENAME = "data-egress"
HASH_KEY = "pipeline_name"
RANGE_KEY = "source_prefix"


def test_process_message():
    json_file = open("tests/sqs_message.json")
    message_body = json.load(json_file)
    response = {"Messages": [{"Body": json.dumps(message_body)}]}
    s3_prefixes = sqs_listener.process_messages(response["Messages"])
    assert s3_prefixes[0] == "data-egress-testing/2021-01-10/"


def test_process_message_with_error():
    json_file = open("tests/sqs_message_no_records.json")
    message_body = json.load(json_file)
    response = {"Messages": [{"Body": json.dumps(message_body)}]}
    with pytest.raises(KeyError) as ex:
        sqs_listener.process_messages(response["Messages"])
    assert (
        str(ex.value)
        == "\"Key: 's3' not found when retrieving the prefix from sqs message\""
    )


def test_process_message_wrong_formatted_prefix_1():
    json_file = open("tests/sqs_message_wrong_formatted_prefix_1.json")
    message_body = json.load(json_file)
    response = {"Messages": [{"Body": json.dumps(message_body)}]}
    s3_prefixes = sqs_listener.process_messages(response["Messages"])
    assert len(s3_prefixes) == 0


def test_process_message_wrong_formatted_prefix_2():
    json_file = open("tests/sqs_message_wrong_formatted_prefix_2.json")
    message_body = json.load(json_file)
    response = {"Messages": [{"Body": json.dumps(message_body)}]}
    s3_prefixes = sqs_listener.process_messages(response["Messages"])
    assert len(s3_prefixes) == 0


def test_process_dynamo_db_response():
    records = [S3PrefixAndDynamoRecord("data-egress-testing/", [])]
    with pytest.raises(Exception) as ex:
        sqs_listener.process_dynamo_db_response(records)
    assert (
        str(ex.value)
        == "No records found in dynamo db for the s3_prefix data-egress-testing/"
    )


def test_process_dynamo_db_response_1():
    records = [
        S3PrefixAndDynamoRecord(
            "data-egress-testing/", [{"source_bucket": "123"}, {"source_bucket": "456"}]
        )
    ]
    with pytest.raises(Exception) as ex:
        sqs_listener.process_dynamo_db_response(records)
    assert str(ex.value) == "More than 1 record for the s3_prefix data-egress-testing/"


def test_process_dynamo_db_response_2():
    records = [
        S3PrefixAndDynamoRecord("data-egress-testing/", [{"destination_bucket": "123"}])
    ]
    with pytest.raises(KeyError) as ex:
        sqs_listener.process_dynamo_db_response(records)
    assert (
        str(ex.value)
        == "\"Key: 'source_bucket' not found when retrieving from dynamodb response\""
    )


@mock_sqs
@mock_dynamodb2
@mock_s3
def test_all(monkeypatch):
    sqs_client = boto3.client("sqs")
    json_file = open("tests/sqs_message.json")
    sqs_client = boto3.client("sqs")
    json_file = open("tests/sqs_message.json")
    response = json.load(json_file)
    msg_json_str = json.dumps(response)
    args = mock_args()
    args.sqs_url = mock_get_sqs_resource().url
    sqs_client.send_message(QueueUrl=args.sqs_url, MessageBody=msg_json_str)
    monkeypatch.setattr(
        sqs_listener, "get_dynamodb_resource", mock_get_dynamodb_resource
    )
    monkeypatch.setattr(sqs_listener, "call_dks", mock_call_dks)
    s3_client = mock_get_s3_client()
    sqs_listener.listen(args, s3_client)
    compressed_data = s3_client.get_object(
        Bucket=DESTINATION_BUCKET, Key=f"{DESTINATION_PREFIX}some_file.gz"
    )["Body"].read()
    print(f"compressed datataa : {compressed_data}")
    decompressed = decompress(compressed_data).decode()
    assert decompressed == "test_data"


@mock_sqs
def mock_get_sqs_resource():
    sqs = boto3.resource("sqs")
    test_sqs_queue = sqs.create_queue(QueueName="test-sqs-queue")
    return test_sqs_queue


@mock_dynamodb2
def mock_get_dynamodb_resource():
    dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
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
    table.put_item(
        Item={
            HASH_KEY: RECIPIENT_NAME,
            RANGE_KEY: SOURCE_PREFIX,
            "source_bucket": SOURCE_BUCKET,
            "destination_bucket": DESTINATION_BUCKET,
            "destination_prefix": DESTINATION_PREFIX,
            "transfer_type": S3_TRANSFER_TYPE,
            "recipient_name": RECIPIENT_NAME,
            "compress": True,
            "compression_fmt": "gzip",
        }
    )
    return dynamodb


@mock_s3
def mock_get_s3_client():
    s3_client = boto3.client(service_name="s3", region_name="us-east-1")
    s3_client.create_bucket(Bucket=SOURCE_BUCKET)
    s3_client.create_bucket(Bucket=DESTINATION_BUCKET)
    encrypted = encrypt_data("test_data")
    print(f"encrypted: {encrypted}")
    s3_client.put_object(
        Body=encrypted,
        Bucket=SOURCE_BUCKET,
        Key=f"{SOURCE_PREFIX}some_file.enc",
        Metadata={
            "iv": "BDva/T7HssDYMtyLfn/afw==",
            "ciphertext": "test_ciphertext",
            "datakeyencryptionkeyid": "123",
        },
    )
    return s3_client


def decompress(data):
    return zlib.decompress(data, 16 + zlib.MAX_WBITS)


def encrypt_data(data):
    return encrypt(
        5627699127241421480342634160438893183, "UBkbtizlrjYs5kZch3CwCg==", data.encode()
    )


def encrypt(initialisation_vector, datakey, unencrypted_bytes):
    counter = Counter.new(AES.block_size * 8, initial_value=initialisation_vector)
    aes = AES.new(base64.b64decode(datakey), AES.MODE_CTR, counter=counter)
    return aes.encrypt(unencrypted_bytes)


def mock_args():
    args = argparse.Namespace()
    args.log_level = logging.INFO
    args.is_test = True
    return args


def mock_call_dks(cek, kek, args):
    return "UBkbtizlrjYs5kZch3CwCg=="
