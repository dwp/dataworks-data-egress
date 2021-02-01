import argparse
import base64
import json
import logging
import re
import os
import zlib
import boto3
import requests
from Crypto.Cipher import AES
from Crypto.Util import Counter
from boto3.dynamodb.conditions import Key
from data_egress import logger_utils

BUCKET_OWNER_FULL_CONTROL_ACL = "bucket-owner-full-control"
ROLE_ARN = "role_arn"
S3 = "s3"
DYNAMODB = "dynamodb"
LIST_OBJECTS_V2 = "list_objects_v2"
KEY = "Key"
CONTENTS = "Contents"
ENC_EXTENSION = ".enc"
ITEMS = "Items"
MESSAGES = "Messages"
SQS = "sqs"
ATTRIBUTES = "Attributes"
NUMBER_OF_MESSAGES = "ApproximateNumberOfMessages"
APPROXIMATE_RECEIVE_COUNT = "ApproximateReceiveCount"
ALL = "All"
BODY = "Body"
DATA_ENCRYPTION_KEY_ID = "datakeyencryptionkeyid"
CIPHER_TEXT = "ciphertext"
IV = "iv"
METADATA = "Metadata"
PIPELINE_SUCCESS_FLAG = "pipeline_success.flag"
KEY_RECORDS = "Records"
KEY_MESSAGE_ID = "MessageId"
KEY_RECEIPT_HANDLE = "ReceiptHandle"
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
HASH_KEY = "source_prefix"
RANGE_KEY = "pipeline_name"

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
        compress=None,
        compression_fmt=None,
        role_arn=None,
    ):
        self.source_bucket = source_bucket
        self.source_prefix = source_prefix
        self.destination_bucket = destination_bucket
        self.destination_prefix = destination_prefix
        self.transfer_type = transfer_type
        self.compress = compress
        self.compression_fmt = compression_fmt
        self.role_arn = role_arn


def listen(args, s3_client):
    """Listens to the sqs messages.

    Arguments:
    args: args like sqs_url , dks url will be passed in it
    s3_client: s3_client to connect to s3
    """
    logger_utils.setup_logging(args)
    sqs_client = get_client(service_name=SQS, region_name=args.region_name)
    while True:
        try:
            response = sqs_client.get_queue_attributes(
                QueueUrl=args.sqs_url, AttributeNames=[NUMBER_OF_MESSAGES]
            )
            available_msg_count = int(response[ATTRIBUTES][NUMBER_OF_MESSAGES])
            logger.info(f"available messages count: {available_msg_count}")
            if available_msg_count and available_msg_count > 0:
                response = sqs_client.receive_message(
                    QueueUrl=args.sqs_url, AttributeNames=[ALL], MaxNumberOfMessages=1
                )
                logger.debug(f"Response received from queue: {response}")
                messages = response[MESSAGES]
                s3_prefixes = []
                for message in messages:
                    previous_deliveries_count = int(
                        message[ATTRIBUTES][APPROXIMATE_RECEIVE_COUNT]
                    )
                    if previous_deliveries_count > args.max_retries:
                        logger.warning(
                            f"message: {message[KEY_MESSAGE_ID]} previously delivered: {previous_deliveries_count} more than max retries: {args.max_retries}"
                        )
                        # configure in future dlq to receive if message processing fails more than configured retries
                    s3_prefixes = get_to_be_processed_s3_prefixes(message)
                    logger.info(f"s3 prefixes to be processed are : {s3_prefixes}")
                    dynamodb = get_dynamodb_resource(args.region_name)
                    s3prefix_and_dynamodb_records = query_dynamodb(
                        s3_prefixes, dynamodb
                    )
                    dynamo_records = process_dynamo_db_response(
                        s3prefix_and_dynamodb_records
                    )
                    start_processing(s3_client, dynamo_records, args)
                    delete_message_from_sqs(sqs_client, args.sqs_url, message)
                if args.is_test:
                    break
        except Exception as ex:
            logger.error(
                f"Failed to process the messages with s3 prefixes {s3_prefixes}: {str(ex)}"
            )
            if args.is_test:
                break


def delete_message_from_sqs(sqs_client, sqs_url, message):
    """Delete processed messages from sqs to prevent duplication.

    Arguments:
        sqs_client: SQS client object
        sqs_url: SQS queue URL
        message: Response received from sqs
    """
    try:
        logger.info(
            f"Deleting message with id {message[KEY_MESSAGE_ID]} from SQS queue "
        )
        sqs_client.delete_message(
            QueueUrl=sqs_url, ReceiptHandle=message[KEY_RECEIPT_HANDLE]
        )
    except Exception as ex:
        logger.error(
            f"Failed to delete message with id {message[KEY_MESSAGE_ID]} from SQS queue: {str(ex)}"
        )


def get_to_be_processed_s3_prefixes(message):
    """Processes response received from listening to sqs.

    Arguments:
        message: Response received from sqs
    """
    s3_prefixes = []
    s3_keys = []
    try:
        message_body = json.loads(message[BODY])
        for event in message_body[KEY_RECORDS]:
            s3_key = event[KEY_S3][KEY_OBJECT][KEY_KEY]
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
        response = table.query(KeyConditionExpression=Key(HASH_KEY).eq(s3_prefix))
        items = response[ITEMS]
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
            logger.error(f"No records found in dynamo db for the s3_prefix {s3_prefix}")
        elif len(records) > 1:
            logger.error(f"More than 1 record for the s3_prefix {s3_prefix}")
        else:
            try:
                return get_dynamo_records(records)
            except Exception as ex:
                logger.error(
                    f"Key: {str(ex)} not found when retrieving from dynamodb response"
                )


def get_dynamo_records(records):
    record = records[0]
    dynamo_records = []
    compress = None
    compression_fmt = None
    role_arn = None
    destination_bucket = None
    destination_prefix = None
    source_bucket = record[DYNAMO_DB_ITEM_SOURCE_BUCKET]
    source_prefix = record[DYNAMO_DB_ITEM_SOURCE_PREFIX]
    transfer_type = record[DYNAMO_DB_ITEM_TRANSFER_TYPE]
    logger.info(f"{source_bucket} {source_prefix}")
    if transfer_type == S3_TRANSFER_TYPE:
        destination_bucket = record[DYNAMO_DB_ITEM_DESTINATION_BUCKET]
        destination_prefix = record[DYNAMO_DB_ITEM_DESTINATION_PREFIX]
    if DYNAMO_DB_ITEM_COMPRESS in record:
        compress = record[DYNAMO_DB_ITEM_COMPRESS]
        if compress:
            compression_fmt = record[DYNAMO_DB_ITEM_COMPRESSION_FMT]
    if ROLE_ARN in record:
        role_arn = record[ROLE_ARN]
    dynamo_records.append(
        DynamoRecord(
            source_bucket,
            source_prefix,
            destination_bucket,
            destination_prefix,
            transfer_type,
            compress,
            compression_fmt,
            role_arn,
        )
    )
    return dynamo_records


def start_processing(s3_client, dynamo_records, args):
    """Decrypts, compresses and saves data to the destination

    Arguments:
    s3_client: Client to connect to s3
    dynamo_records: Records looked up in dynamodb table for s3 prefixes
    args: args passed from client
    """
    for dynamo_record in dynamo_records:
        source_bucket = dynamo_record.source_bucket
        source_prefix = dynamo_record.source_prefix
        keys = get_all_s3_keys(s3_client, source_bucket, source_prefix)
        logger.info(f"Processing keys: {keys} for the prefix: {source_prefix}")
        for key in keys:
            s3_object = s3_client.get_object(Bucket=source_bucket, Key=key)
            metadata = s3_object[METADATA]
            logger.info(f"Metadata for the s3 key : {metadata}")
            iv = metadata[IV]
            ciphertext = metadata[CIPHER_TEXT]
            datakeyencryptionkeyid = metadata[DATA_ENCRYPTION_KEY_ID]
            plain_text_key = get_plaintext_key_calling_dks(
                ciphertext, datakeyencryptionkeyid, args
            )
            streaming_data = s3_client.get_object(Bucket=source_bucket, Key=key)[BODY]
            data = decrypt(plain_text_key, iv, streaming_data)
            if dynamo_record.compress is not None and dynamo_record.compress:
                data = compress(data)
            file_name = key.replace(source_prefix, "")
            file_name_without_enc = file_name.replace(ENC_EXTENSION, "")
            destination_bucket = dynamo_record.destination_bucket
            destination_prefix = dynamo_record.destination_prefix
            role_arn = dynamo_record.role_arn
            if role_arn is not None:
                sts_response = assume_role(role_arn, "session_name", 3600)
                s3_client = get_s3_client_with_assumed_role(sts_response)
            save(
                s3_client,
                file_name_without_enc,
                destination_bucket,
                destination_prefix,
                data
            )


def get_all_s3_keys(s3_client, source_bucket, source_prefix):
    """Decrypts, compresses and saves data to the destination

    Arguments:
    s3_client: Client to connect to s3
    source_bucket: source bucket
    source_prefix: prefix of the source bucket
    """
    keys = []
    paginator = s3_client.get_paginator(LIST_OBJECTS_V2)
    pages = paginator.paginate(Bucket=source_bucket, Prefix=source_prefix)
    logger.info(
        f"Getting all keys in bucket: {source_bucket} for prefix: {source_prefix}"
    )
    for page in pages:
        for obj in page[CONTENTS]:
            key = obj[KEY]
            if (PIPELINE_SUCCESS_FLAG not in key) and (source_prefix != key):
                keys.append(key)
    return keys


def get_plaintext_key_calling_dks(encryptedkey, keyencryptionkeyid, args):
    """Gets plain text key to decrypt from dks

    Arguments:
    encryptedkey: Encrypted key from metadata
    keyencryptionkeyid: key encryption key of the envelope encryption taken from metadata
    args: args passed from client
    """
    if keys_map.get(encryptedkey):
        key = keys_map[encryptedkey]
    else:
        key = call_dks(encryptedkey, keyencryptionkeyid, args)
        keys_map[encryptedkey] = key
    return key


def call_dks(cek, kek, args):
    """Gets plain text key to decrypt from dks

    Arguments:
    cek: content encryption key
    kek: key encryption key of the envelope encryption taken from metadata
    args: args passed from client
    """
    logger.info("Calling DKS to retrieve plaintext key")
    try:
        url = f"{args.dks_url}/datakey/actions/decrypt"
        params = {"keyId": kek}
        result = requests.post(
            url,
            params=params,
            data=cek,
            cert=(
                "/etc/ssl/certs/data_egress.crt",
                "/etc/ssl/private/data_egress.key",
            ),
            verify="/usr/local/share/ca-certificates/data_egress_ca.pem",
        )
        content = result.json()
    except BaseException as ex:
        logger.error(f"Problem calling DKS {str(ex)}")
        return
    return content["plaintextDataKey"]


def decrypt(plain_text_key, iv_key, data):
    """Gets plain text key to decrypt from dks

    Arguments:
    plain_text_key: plain key retrieved from dks
    iv_key: initialisation vector
    data: unencrypted data
    """
    logger.info("Decrypting data")
    try:
        iv_int = int(base64.b64decode(iv_key).hex(), 16)
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        aes = AES.new(base64.b64decode(plain_text_key), AES.MODE_CTR, counter=ctr)
        decrypted = aes.decrypt(data.read())
        return decrypted
    except BaseException as ex:
        logger.error(f"Problem decrypting data {str(ex)}")


def compress(decrypted):
    """Compresses the data

    Arguments:
    decrypted: Decrypted bytes
    """
    logger.info("Compressing decrypted data")
    compress = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    compressed_data = compress.compress(decrypted)
    compressed_data += compress.flush()
    return compressed_data


def save(s3_client, file_name, destination_bucket, destination_prefix, data):
    """Compresses the data

    Arguments:
    s3_client: client to connect to s3
    file_name: Name of the file in the destination bucket
    destination_bucket: destination bucket
    destination_prefix: destination prefix
    data: Data to be uploaded
    """
    try:
        key = f"{destination_prefix}{file_name}"
        logger.info(f"saving to bucket:{destination_bucket} with key: {key}")
        s3_client.put_object(
            ACL=BUCKET_OWNER_FULL_CONTROL_ACL,
            Body=data,
            Bucket=destination_bucket,
            Key=key,
        )
        logger.info(f"Saved key: {key} in destination bucket {destination_bucket}")
    except Exception as ex:
        logger.error(f"Exception while saving {str(ex)}")


def get_client(service_name, region_name):
    """gets Boto3 client

    Arguments:
    service_name: service name
    region_name: region name
    """
    client = boto3.client(service_name, region_name)
    return client


def get_dynamodb_resource(region_name):
    """gets Dynamodb client

    Arguments:
    region_name: region name
    """
    return boto3.resource(DYNAMODB, region_name=region_name)


def get_s3_client():
    """gets S3 client"""
    return boto3.client(S3)


# is region needed?
def get_s3_client_with_assumed_role(sts_reponse):
    """gets S3 client
      Arguments:
    sts_reponse: response from sts service
    """
    access_key_id = sts_reponse["AccessKeyId"]
    secret_access_key = sts_reponse["SecretAccessKey"]
    session_token = sts_reponse["SessionToken"]
    logger.info(f"session : {access_key_id} {secret_access_key} {session_token}")
    return boto3.client(
        "s3",
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token,
    )


def parse_args():
    """Define and parse command line args."""

    parser = argparse.ArgumentParser(
        description="Receive args provided to spark submit job"
    )
    # Parse command line inputs and set defaults90
    parser.add_argument("--sqs_url", default="")
    parser.add_argument("--dks_url", default="")
    parser.add_argument("--log_level", default="INFO")
    parser.add_argument("--region_name", default="eu-west-2")
    parser.add_argument("--is_test", default=False)
    parser.add_argument("--max_retries", default=3)

    args = parser.parse_args()
    if "sqs_url" in os.environ:
        args.sqs_url = os.environ["sqs_url"]

    if "dks_url" in os.environ:
        args.dks_url = os.environ["dks_url"]

    if "max_retries" in os.environ:
        args.max_retries = os.environ["max_retries"]

    return args


def assume_role(aws_role_arn, session_name, session_timeout):
    """Assumes the role needed for the boto3 session.

    Keyword arguments:
    aws_role_arn: Role to be assumed
    session_name: Name of the boto3 session
    session_timeout: timeout for the session
    """
    logger.info(f"role arn is {aws_role_arn}")
    try:
        sts_client = boto3.client("sts")
        assume_role_dict = sts_client.assume_role(
            RoleArn=aws_role_arn,
            RoleSessionName=session_name,
            DurationSeconds=session_timeout,
        )

        return assume_role_dict["Credentials"]
    except Exception as ex:
        logger.error(f"error while assuming role {str(ex)}")


def main():
    """Entry point to the program"""
    args = parse_args()
    s3_client = get_s3_client()
    listen(args, s3_client)


if __name__ == "__main__":
    main()
