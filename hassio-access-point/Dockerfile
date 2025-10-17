ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base:latest
FROM $BUILD_FROM

LABEL maintainer="Matt Longman <git@mattlongman.com>"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV LANG=C.UTF-8

# Install required packages for Home Assistant OS compatibility
RUN apk update && \
apk add --no-cache \
    bash \
    iw \
    hostapd \
    networkmanager \
    networkmanager-cli \
    net-tools \
    sudo \
    dnsmasq \
    iptables \
    ip6tables \
    iproute2 \
    gawk && \
rm -rf /var/cache/apk/*

COPY hostapd.conf /
COPY dnsmasq.conf /

COPY run.sh /
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
