FROM debian:stretch-slim

LABEL Description="Alfis Alternative Free Identity System"
LABEL URL="https://github.com/Revertron/Alfis/releases"

ARG arch=amd64
ARG srv_port=4244
ARG dns_port=53

RUN apt-get update -y && \
    apt-get install -y curl && \
    curl -SsL "https://github.com/Revertron/Alfis/releases/download/$(curl --silent "https://api.github.com/repos/Revertron/Alfis/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')/alfis-${arch}-$(curl --silent "https://api.github.com/repos/Revertron/Alfis/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')-nogui.deb" -o /tmp/alfis.deb  && \
    dpkg -i /tmp/alfis.deb && \
    apt-get purge -y curl && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /tmp/* && \
    rm -rf /var/lib/{apt,dpkg,cache,log}/

EXPOSE ${srv_port}
EXPOSE ${dns_port}
EXPOSE ${dns_port}/udp

WORKDIR /var/lib/alfis

CMD ["/usr/bin/alfis", "-n", "-c", "/etc/alfis.conf"]
