FROM debian:bookworm-20250407-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      openvpn \
      iptables \
      inotify-tools \
      gettext-base \
      curl \
      openssl \
      cron \
      easy-rsa && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/openvpn /config /scripts /secret

COPY config/ /config/
COPY scripts/ /scripts/
RUN chmod +x /scripts/*

EXPOSE 1194/tcp

ENTRYPOINT ["/scripts/entrypoint.sh"]