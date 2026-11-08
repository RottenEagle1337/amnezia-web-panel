# Mirrors client/server_scripts/wireguard/Dockerfile (dev branch).
FROM alpine:3.15
RUN apk add --no-cache curl wireguard-tools dumb-init
RUN apk --update upgrade --no-cache
RUN mkdir -p /opt/amnezia
RUN printf '#!/bin/bash\ntail -f /dev/null\n' > /opt/amnezia/start.sh && chmod a+x /opt/amnezia/start.sh
ENTRYPOINT ["dumb-init", "/opt/amnezia/start.sh"]
CMD [""]
