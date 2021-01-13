import boto3


def get_client(service_name):
    client = boto3.client(service_name)
    return client
