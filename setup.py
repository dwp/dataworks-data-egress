"""setuptools packaging."""

import setuptools

setuptools.setup(
    name="data_egress",
    version="0.0.1",
    author="DWP DataWorks",
    author_email="dataworks@digital.uc.dwp.gov.uk",
    description="data_egress",
    long_description="data_egress",
    long_description_content_type="text/markdown",
    entry_points={
        "console_scripts": [
            "sqs-listener=data_egress.sqs_listener:main"
        ]
    },
    package_dir={"": "src"},
    packages=setuptools.find_packages("src"),
    install_requires=["boto3", "requests", "pycryptodome"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
