#!/bin/sh

set -e

export HTTP_PROXY="http://${internet_proxy}:3128"
export HTTPS_PROXY="$HTTP_PROXY"
export NO_PROXY="${non_proxied_endpoints},${dks_fqdn}"


export ACM_KEY_PASSWORD=$(uuidgen -r)
echo "Retrieving acm certs"
acm-cert-retriever \
--acm-cert-arn "${acm_cert_arn}" \
--acm-key-passphrase "$ACM_KEY_PASSWORD" \
--private-key-alias "${private_key_alias}" \
--truststore-aliases "${truststore_aliases}" \
--truststore-certs "${truststore_certs}"

cd /usr/local/share/ca-certificates/
touch data_egress_ca.pem

TRUSTSTORE_ALIASES="${truststore_aliases}"
for F in $(echo $TRUSTSTORE_ALIASES | sed "s/,/ /g"); do
 (cat "$F.crt"; echo) >> data_egress_ca.pem;
done

exec "${@}"
