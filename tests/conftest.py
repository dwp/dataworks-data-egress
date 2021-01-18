import os
import pytest

TESTING = "testing"


@pytest.fixture(scope="module")
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = TESTING
    os.environ["AWS_SECRET_ACCESS_KEY"] = TESTING
    os.environ["AWS_SECURITY_TOKEN"] = TESTING
    os.environ["AWS_SESSION_TOKEN"] = TESTING
