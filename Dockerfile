FROM python:3.8-alpine3.10

WORKDIR /
COPY ./ /app
WORKDIR /app
RUN apk --update --no-cache add gcc musl-dev libffi-dev openssl-dev
RUN python setup.py install

ENTRYPOINT ["python", "/usr/local/bin/sqs-listener"]
