FROM python:3.8.10-alpine3.13

RUN mkdir data-egress

WORKDIR /
COPY ./ /app
WORKDIR /app

RUN pip install --upgrade pip
ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1

ENV acm_cert_helper_version="0.37.0"
RUN echo "===> Installing Dependencies ..." \
    && echo "===> Updating base packages ..." \
    && apk update \
    && apk upgrade \
    && echo "==Update done==" \
    && apk add --no-cache ca-certificates \
    && apk add --no-cache util-linux \
    && echo "===> Installing acm_pca_cert_generator ..." \
    && apk add --no-cache g++ gcc musl-dev libffi-dev openssl-dev gcc cargo  \
    && pip3 install https://github.com/dwp/acm-pca-cert-generator/releases/download/${acm_cert_helper_version}/acm_cert_helper-${acm_cert_helper_version}.tar.gz \
    && echo "==Dependencies done=="
RUN python setup.py install

# Set user to run the process as in the docker contianer
ENV USER_NAME=root
ENV GROUP_NAME=root

RUN chown -R $USER_NAME.$GROUP_NAME /etc/ssl/
RUN chown -R $USER_NAME.$GROUP_NAME /usr/local/share/ca-certificates/
RUN chown -R $USER_NAME.$GROUP_NAME /app
RUN chown -R $USER_NAME.$GROUP_NAME /var
RUN chown -R $USER_NAME.$GROUP_NAME /data-egress
RUN chmod a+rw /var/log
RUN chmod -R a+rwx /etc/ssl/
RUN chmod -R a+rwx /usr/local/share/ca-certificates/
RUN chmod -R a+rwx /data-egress
USER $USER_NAME

# Data volume
VOLUME [ "/data-egress" ]

ENTRYPOINT ["./entrypoint.sh"]
CMD ["python", "/usr/local/bin/sqs-listener"]
