import argparse
import base64
import json
import logging
import re
import uuid
import zlib

import boto3
import requests
from Crypto.Cipher import AES
from Crypto.Util import Counter
from boto3.dynamodb.conditions import Key
from data_egress import logger_utils

BODY = "Body"
DATA_ENCRYPTION_KEY_ID = "datakeyencryptionkeyid"
CIPHER_TEXT = "ciphertext"
IV = "iv"
METADATA = "Metadata"
sqs_count = 0
PIPELINE_SUCCESS_FLAG = "pipeline_success.flag"
KEY_RECORDS = "Records"
KEY_S3 = "s3"
KEY_OBJECT = "object"
KEY_KEY = "key"
REGEX_PATTERN = r"^[\w\/-]*pipeline_success.flag$"
DATA_EGRESS_DYNAMO_DB_TABLE = "data-egress"
DYNAMO_DB_ITEM_SOURCE_BUCKET = "source_bucket"
DYNAMO_DB_ITEM_DESTINATION_BUCKET = "destination_bucket"
DYNAMO_DB_ITEM_COMPRESS = "compress"
DYNAMO_DB_ITEM_COMPRESSION_FMT = "compression_fmt"
DYNAMO_DB_ITEM_SOURCE_PREFIX = "source_prefix"
DYNAMO_DB_ITEM_DESTINATION_PREFIX = "destination_prefix"
DYNAMO_DB_ITEM_TRANSFER_TYPE = "transfer_type"
S3_TRANSFER_TYPE = "S3"
keys_map = {}

logger = logging.getLogger("sqs_listener")


class S3PrefixAndDynamoRecord:
    def __init__(self, s3_prefix, dynamodb_records):
        self.s3_prefix = s3_prefix
        self.dynamodb_records = dynamodb_records


class DynamoRecord:
    def __init__(
        self,
        source_bucket,
        source_prefix,
        destination_bucket,
        destination_prefix,
        transfer_type,
        compress,
        compression_fmt,
    ):
        self.source_bucket = source_bucket
        self.source_prefix = source_prefix
        self.destination_bucket = destination_bucket
        self.destination_prefix = destination_prefix
        self.transfer_type = transfer_type
        self.compress = compress
        self.compression_fmt = compression_fmt


def listen(args, s3_client):
    logger_utils.setup_logging(logger, args.log_level)
    sqs_client = get_client(service_name="sqs", region_name=args.region_name)
    while True:
        response = sqs_client.get_queue_attributes(
            QueueUrl=args.sqs_url, AttributeNames=["ApproximateNumberOfMessages"]
        )
        available_msg_count = int(response["Attributes"]["ApproximateNumberOfMessages"])
        logger.info(f"available messages count: {available_msg_count}")
        if available_msg_count and available_msg_count > 0:
            # TODO Recheck on the attribute names
            response = sqs_client.receive_message(
                QueueUrl=args.sqs_url, AttributeNames=["All"]
            )
            # TODO handle keyerror
            messages = response["Messages"]
            logger.info(f"Messages(s) received from queue: {json.dumps(messages)}")
            s3_prefixes = process_messages(messages)
            dynamodb = get_dynamodb_resource(args.region_name)
            s3prefix_and_dynamodb_records = query_dynamodb(s3_prefixes, dynamodb)
            dynamo_records = process_dynamo_db_response(s3prefix_and_dynamodb_records)
            start_processing(s3_client, dynamo_records, args)
            if args.is_test:
                break


# TODO More than one message wil be received in a single batch
def process_messages(messages):
    """Processes response received from listening to sqs.

    Arguments:
        messages: Response received from sqs
    """
    s3_prefixes = []
    s3_keys = []
    try:
        for message in messages:
            message_body = json.loads(message[BODY])
            for event in message_body[KEY_RECORDS]:
                s3_key = event[KEY_S3][KEY_OBJECT][KEY_KEY]
                logger.info(f"s3_key : {s3_key}")
                s3_keys.append(s3_key)
    except Exception as ex:
        logger.error(
            f"Key: {str(ex)} not found when retrieving the prefix from sqs message"
        )
        raise KeyError(
            f"Key: {str(ex)} not found when retrieving the prefix from sqs message"
        )
    for s3_key in s3_keys:
        if re.match(REGEX_PATTERN, s3_key):
            s3_prefix = s3_key.replace(PIPELINE_SUCCESS_FLAG, "")
            s3_prefixes.append(s3_prefix)
        else:
            logger.error(f"{s3_key} is not in the pattern {REGEX_PATTERN}")
    return s3_prefixes


def query_dynamodb(s3_prefixes, dynamodb):
    """Query  DynamoDb status table for a given correlation id.

    Arguments:
        s3_prefixes (string): source bucket prefixes to query dynamo db table
    """
    table = dynamodb.Table(DATA_EGRESS_DYNAMO_DB_TABLE)
    s3prefix_and_dynamodb_records = []
    for s3_prefix in s3_prefixes:
        response = table.query(
            KeyConditionExpression=Key("pipeline_name").eq("OpsMI")
            & Key("source_prefix").eq(s3_prefix)
        )
        items = response["Items"]
        logger.info(f"dynamodb items for {s3_prefix}: {items}")
        s3prefix_and_dynamodb_records.append(S3PrefixAndDynamoRecord(s3_prefix, items))
    return s3prefix_and_dynamodb_records


def process_dynamo_db_response(s3prefix_and_dynamodb_records):
    """Processes the dynamo db response

    Arguments:
    s3prefix_and_dynamodb_records: List of records found in dynamo db for the query
    """
    for s3prefix_and_dynamodb_record in s3prefix_and_dynamodb_records:
        s3_prefix = s3prefix_and_dynamodb_record.s3_prefix
        records = s3prefix_and_dynamodb_record.dynamodb_records
        if len(records) == 0:
            raise Exception(
                f"No records found in dynamo db for the s3_prefix {s3_prefix}"
            )
        elif len(records) > 1:
            raise Exception(f"More than 1 record for the s3_prefix {s3_prefix}")
        else:
            try:
                record = records[0]
                dynamo_records = []
                source_bucket = record[DYNAMO_DB_ITEM_SOURCE_BUCKET]
                source_prefix = record[DYNAMO_DB_ITEM_SOURCE_PREFIX]
                transfer_type = record[DYNAMO_DB_ITEM_TRANSFER_TYPE]
                logger.info(f"so ooo {source_bucket} {source_prefix}")
                if transfer_type == S3_TRANSFER_TYPE:
                    destination_bucket = record[DYNAMO_DB_ITEM_DESTINATION_BUCKET]
                    destination_prefix = record[DYNAMO_DB_ITEM_DESTINATION_PREFIX]
                    compress = record[DYNAMO_DB_ITEM_COMPRESS]
                    compression_fmt = record[DYNAMO_DB_ITEM_COMPRESSION_FMT]
                    dynamo_records.append(
                        DynamoRecord(
                            source_bucket,
                            source_prefix,
                            destination_bucket,
                            destination_prefix,
                            transfer_type,
                            compress,
                            compression_fmt,
                        )
                    )
                    logger.info(f"fffff {dynamo_records}")
                    return dynamo_records
            except Exception as ex:
                logger.error(
                    f"Key: {str(ex)} not found when retrieving from dynamodb response"
                )
                raise KeyError(
                    f"Key: {str(ex)} not found when retrieving from dynamodb response"
                )


def start_processing(s3_client, dynamo_records, args):
    for dynamo_record in dynamo_records:
        source_bucket = dynamo_record.source_bucket
        source_prefix = dynamo_record.source_prefix
        keys = get_all_s3_keys(s3_client, source_bucket, source_prefix)
        for key in keys:
            s3_object = s3_client.get_object(Bucket=source_bucket, Key=key)
            iv = s3_object[METADATA][IV]
            ciphertext = s3_object[METADATA][CIPHER_TEXT]
            datakeyencryptionkeyid = s3_object[METADATA][DATA_ENCRYPTION_KEY_ID]
            plain_text_key = get_plaintext_key_calling_dks(
                ciphertext, datakeyencryptionkeyid, args
            )
            streaming_data = s3_client.get_object(Bucket=source_bucket, Key=key)["Body"]
            data = decrypt(plain_text_key, iv, streaming_data)
            if dynamo_record.compress:
                data = compress(data)
            # credentials_dict = assume_role()
            # boto3.session.Session(
            #     aws_access_key_id=credentials_dict["AccessKeyId"],
            #     aws_secret_access_key=credentials_dict["SecretAccessKey"],
            #     aws_session_token=credentials_dict["SessionToken"],
            # )
            file_name = key.replace(source_prefix, "")
            file_name_without_enc = file_name.replace(".enc", "")
            destination_bucket = dynamo_record.destination_bucket
            destination_prefix = dynamo_record.destination_prefix
            logger.info(f"compresssssed : {data}")
            save(
                s3_client,
                file_name_without_enc,
                destination_bucket,
                destination_prefix,
                data,
            )


def get_all_s3_keys(s3_client, source_bucket, source_prefix):
    keys = []
    paginator = s3_client.get_paginator("list_objects_v2")
    pages = paginator.paginate(Bucket=source_bucket, Prefix=source_prefix)
    for page in pages:
        for obj in page["Contents"]:
            keys.append(obj["Key"])
    return keys


def get_plaintext_key_calling_dks(encryptedkey, keyencryptionkeyid, args):
    if keys_map.get(encryptedkey):
        key = keys_map[encryptedkey]
    else:
        key = call_dks(encryptedkey, keyencryptionkeyid, args)
        keys_map[encryptedkey] = key
    return key


def call_dks(cek, kek, args):
    try:
        url = args.dks_url
        params = {"keyId": kek}
        result = requests.post(
            url,
            params=params,
            data=cek,
            cert=(
                "/etc/pki/tls/certs/private_key.crt",
                "/etc/pki/tls/private/private_key.key",
            ),
            verify="/etc/pki/ca-trust/source/anchors/analytical_ca.pem",
        )
        content = result.json()
    except BaseException as ex:
        logger.error(f"Problem calling DKS {str(ex)}")
    return content["plaintextDataKey"]


def decrypt(plain_text_key, iv_key, data):
    try:
        iv_int = int(base64.b64decode(iv_key).hex(), 16)
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        aes = AES.new(base64.b64decode(plain_text_key), AES.MODE_CTR, counter=ctr)
        decrypted = aes.decrypt(data.read())
        return decrypted
    except BaseException as ex:
        logger.error(f"Problem decrypting data {str(ex)}")


def compress(decrypted):
    logger.info(f"decrypted: {decrypted}")
    compress = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    compressed_data = compress.compress(decrypted)
    compressed_data += compress.flush()
    return compressed_data


# TODO make comepression format dynamic
def save(s3_client, file_name, destination_bucket, destination_prefix, data):
    try:
        response = s3_client.put_object(
            Body=data,
            Bucket=destination_bucket,
            Key=f"{destination_prefix}{file_name}.gz",
        )
    except Exception as ex:
        logger.error(f"Exception while saving {str(ex)}")


def assume_role():
    """Assumes the role needed for the boto3 session.

    Keyword arguments:
    profile -- the profile name to use (if None, default profile is used)
    """
    global aws_role_arn
    global aws_session_timeout_seconds
    global boto3_session

    if aws_role_arn is None or aws_session_timeout_seconds is None:
        raise AssertionError("abc")

    session_name = "data_egress" + str(uuid.uuid4())
    sts_client = boto3_session.client("sts")
    assume_role_dict = {}
    sts_client.assume_role(
        RoleArn=aws_role_arn,
        RoleSessionName=f"{session_name}",
        DurationSeconds=int(aws_session_timeout_seconds),
    ),

    return assume_role_dict["Credentials"]


def get_client(service_name, region_name):
    client = boto3.client(service_name, region_name)
    return client


def get_dynamodb_resource(region_name):
    return boto3.resource("dynamodb", region_name=region_name)


def get_s3_client():
    return boto3.client("s3")


def parse_args():
    """Define and parse command line args."""

    parser = argparse.ArgumentParser(
        description="Receive args provided to spark submit job"
    )

    # Parse command line inputs and set defaults
    parser.add_argument("--sqs_url", default="")
    parser.add_argument("--dks_url", default="")

    return parser.parse_args()


def main():
    args = parse_args()
    listen(args)


# TODO how to run from command line argument if installed as python package
# TODO why instance variable _sqs_client didnt work?
if __name__ == "__main__":
    main()
