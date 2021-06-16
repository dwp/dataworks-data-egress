#!/bin/sh

# shellcheck disable=SC2155
# shellcheck disable=SC2154

if [ "${internet_proxy}" ]; then
    export http_proxy="http://${internet_proxy}:3128"
    export HTTP_PROXY="$http_proxy"
    export https_proxy="$http_proxy"
    export HTTPS_PROXY="$https_proxy"
    export no_proxy="${non_proxied_endpoints}"
    export NO_PROXY="$no_proxy"
    echo "Using proxy ${internet_proxy}"
fi

HOSTNAME=$(hostname)

if [ "${FETCH_ACM_CERTS:-true}" = "true" ]; then

    KEYSTORE_DIRECTORY="$(mktemp -d)"

    export SECURITY_KEY_PASSWORD="$(uuidgen)"
    export SECURITY_KEYSTORE="$KEYSTORE_DIRECTORY/keystore.jks"
    export SECURITY_KEYSTORE_PASSWORD="$(uuidgen)"
    export SECURITY_KEYSTORE_ALIAS="${private_key_alias}"

    export SECURITY_TRUSTSTORE="$KEYSTORE_DIRECTORY/truststore.jks"
    export SECURITY_TRUSTSTORE_PASSWORD="$(uuidgen)"
    export RETRIEVER_ACM_KEY_PASSPHRASE="$(uuidgen)"

    acm-cert-retriever \
        --acm-cert-arn "${acm_cert_arn}" \
        --log-level INFO \
        --acm-key-passphrase "${RETRIEVER_ACM_KEY_PASSPHRASE}" \
        --keystore-path "$SECURITY_KEYSTORE" \
        --keystore-password "$SECURITY_KEYSTORE_PASSWORD" \
        --private-key-password "$SECURITY_KEY_PASSWORD" \
        --truststore-path "$SECURITY_TRUSTSTORE" \
        --truststore-password "$SECURITY_TRUSTSTORE_PASSWORD" \
        --private-key-alias "$SECURITY_KEYSTORE_ALIAS" \
        --truststore-aliases "${truststore_aliases}" \
        --truststore-certs "${truststore_certs}"

    echo "Cert retrieve result is $? for ${acm_cert_arn}"
else
    echo "Skipping cert generation "
fi

export SPRING_MAIN_BANNER_MODE=off
exec "${@}"
