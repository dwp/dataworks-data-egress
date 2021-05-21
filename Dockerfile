FROM python:3.8-alpine3.10

RUN mkdir data-egress
# Data volume
VOLUME [ "/data-egress" ]

WORKDIR /
COPY ./ /app
WORKDIR /app

RUN python -m pip install --upgrade pip
RUN apk -U upgrade
RUN pip install --no-cache-dir cryptography>=3.2
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
ENV USER_NAME=degr
ENV GROUP_NAME=degr

RUN addgroup $GROUP_NAME
RUN adduser --system --ingroup $GROUP_NAME $USER_NAME
RUN chown -R $USER_NAME.$GROUP_NAME /etc/ssl/
RUN chown -R $USER_NAME.$GROUP_NAME /usr/local/share/ca-certificates/
RUN chown -R $USER_NAME.$GROUP_NAME /app
RUN chown -R $USER_NAME.$GROUP_NAME /var
RUN chmod a+rw /var/log
RUN chmod -R a+rwx /etc/ssl/
RUN chmod -R a+rwx /usr/local/share/ca-certificates/
USER $USER_NAME

ENTRYPOINT ["./entrypoint.sh"]
CMD ["python", "/usr/local/bin/sqs-listener"]
