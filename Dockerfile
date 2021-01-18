FROM python:3.8-alpine3.10

WORKDIR /src
COPY src/ /app
RUN apk --update --no-cache add gcc musl-dev libffi-dev openssl-dev
RUN pip install --no-cache-dir -r /app/requirements.txt

WORKDIR /app
ENTRYPOINT ["python", "sqs_listener.py"]
