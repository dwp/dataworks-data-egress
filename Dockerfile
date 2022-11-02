FROM gradle:jdk16 as build

RUN mkdir -p /build
COPY build.gradle.kts .
COPY settings.gradle.kts .
COPY src/ ./src
RUN gradle build
RUN cp $(ls build/libs/*.jar | grep -v plain) /build/dataworks-data-egress.jar

FROM openjdk:16-alpine

ARG http_proxy_full=""

ENV http_proxy=${http_proxy_full}
ENV https_proxy=${http_proxy_full}
ENV HTTP_PROXY=${http_proxy_full}
ENV HTTPS_PROXY=${http_proxy_full}

RUN echo "ENV http: ${http_proxy}" \
    && echo "ENV https: ${https_proxy}" \
    && echo "ENV HTTP: ${HTTP_PROXY}" \
    && echo "ENV HTTPS: ${HTTPS_PROXY}" \
    && echo "ARG full: ${http_proxy_full}"

ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
ENV acm_cert_helper_version="0.37.0"
RUN apk update \
    && apk upgrade \
    && apk add --no-cache ca-certificates \
    && apk add --no-cache util-linux \
    && apk add --no-cache g++ python3 python3-dev libffi-dev openssl-dev gcc py3-pip rust cargo \
    && pip3 install --upgrade pip setuptools \
    && pip3 install https://github.com/dwp/acm-pca-cert-generator/releases/download/${acm_cert_helper_version}/acm_cert_helper-${acm_cert_helper_version}.tar.gz

ENV USER_NAME=egress
ENV GROUP_NAME=egress

COPY ./entrypoint.sh /

RUN addgroup $GROUP_NAME
RUN adduser --system --ingroup $GROUP_NAME $USER_NAME
RUN chown -R $USER_NAME.$GROUP_NAME /etc/ssl/
RUN chown -R $USER_NAME.$GROUP_NAME /usr/local/share/ca-certificates/

RUN mkdir /dataworks-data-egress
WORKDIR /dataworks-data-egress
COPY --from=build /build/dataworks-data-egress.jar .
COPY ./dataworks-data-egress-keystore.jks ./development-keystore.jks
COPY ./dataworks-data-egress-truststore.jks ./development-truststore.jks

RUN chown -R $USER_NAME.$GROUP_NAME /dataworks-data-egress
RUN chmod -R a+rwx /etc/ssl/
RUN chmod -R a+rwx /usr/local/share/ca-certificates/

USER $USER_NAME

ENTRYPOINT ["/entrypoint.sh"]
CMD ["java", "-Xmx12g", "-jar", "dataworks-data-egress.jar"]
