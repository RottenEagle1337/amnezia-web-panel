FROM alpine:3.15
LABEL maintainer="AmneziaVPN"

ARG XRAY_RELEASE="v26.10.31"

RUN apk add --no-cache curl unzip bash openssl netcat-openbsd dumb-init rng-tools xz
RUN apk --update upgrade --no-cache

RUN mkdir -p /opt/amnezia
RUN echo -e "#!/bin/bash\ntail -f /dev/null" > /opt/amnezia/start.sh
RUN chmod a+x /opt/amnezia/start.sh

RUN mkdir -p /opt/amnezia/xray

RUN curl -L https://github.com/XTLS/Xray-core/releases/download/${XRAY_RELEASE}/Xray-linux-64.zip > /root/xray.zip;\
  unzip /root/xray.zip -d /usr/bin/;\
  chmod a+x /usr/bin/xray;

ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
