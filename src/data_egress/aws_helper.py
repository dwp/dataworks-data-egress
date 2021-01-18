import boto3
import json


def get_client(service_name):
    client = boto3.client(service_name)
    return client


def create_iam_role():
    iam_client = boto3.client("iam")
    trust_relationship_policy_another_iam_user = trust_relaationship()
    role_arn = create_role(iam_client, trust_relationship_policy_another_iam_user)
    policy_arn = create_policy(iam_client, role_arn)
    attach_policy(iam_client, policy_arn)


def create_role(iam_client, trust_relationship_policy_another_iam_user):
    try:
        return iam_client.create_role(
            RoleName="rrrrrr",
            AssumeRolePolicyDocument=json.dumps(
                trust_relationship_policy_another_iam_user
            ),
            Description="This is a test role",
            Tags=[{"Key": "Owner", "Value": "msb"}],
        )
    except Exception as ex:
        if ex.response["Error"]["Code"] == "EntityAlreadyExists":
            return "Role already exists... hence exiting from here"
        else:
            return "Unexpected error occurred... Role could not be created", ex


def create_policy(iam_client, role_arn):
    policy_json = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["ec2:*"], "Resource": "*"}],
    }

    policy_name = "rrrrrr" + "_policy"
    policy_arn = ""

    try:
        policy_res = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=json.dumps(policy_json)
        )
        policy_arn = policy_res["Policy"]["Arn"]
        return policy_arn
    except Exception as ex:
        if ex.response["Error"]["Code"] == "EntityAlreadyExists":
            print("Policy already exists... hence using the same policy")
            policy_arn = "arn:aws:iam::" + "" + ":policy/" + policy_name
        else:
            print("Unexpected error occurred... hence cleaning up", ex)
            iam_client.delete_role(RoleName="rrrrrr")
            print(f"Role could not be created... {str(ex)}")


def attach_policy(iam_client, policy_arn):
    try:
        policy_attach_res = iam_client.attach_role_policy(
            RoleName="rrrrrr", PolicyArn=policy_arn
        )
    except Exception as ex:
        print("Unexpected error occurred... hence cleaning up")
        iam_client.delete_role(RoleName="rrrrrr")
        return "Role could not be created...", ex


def trust_relaationship():
    trust_relationship_policy_another_iam_user = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:user/LiJuan"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    return trust_relationship_policy_another_iam_user
