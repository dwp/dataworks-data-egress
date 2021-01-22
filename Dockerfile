FROM python:3.8-alpine3.10

WORKDIR /
COPY ./ /app
WORKDIR /app
RUN apk --update --no-cache add gcc musl-dev libffi-dev openssl-dev util-linux
RUN python setup.py install

# Set user to run the process as in the docker contianer
ENV USER_NAME=data_egress
ENV GROUP_NAME=data_egress

RUN addgroup $GROUP_NAME
RUN adduser --system --ingroup $GROUP_NAME $USER_NAME

RUN chown -R $USER_NAME.$GROUP_NAME /var
RUN chmod a+rw /var/log
USER $USER_NAME


ENTRYPOINT ["./entrypoint.sh"]
CMD ["python", "/usr/local/bin/sqs-listener"]
