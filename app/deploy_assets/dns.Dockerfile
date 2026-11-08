FROM alpine:3.21
RUN apk add --no-cache unbound
RUN printf '%s\n' \
  'server:' \
  '  verbosity: 0' \
  '  interface: 0.0.0.0' \
  '  access-control: 172.29.172.0/24 allow' \
  '  access-control: 10.8.0.0/16 allow' \
  '  access-control: 10.9.9.0/24 allow' \
  '  do-ip6: no' \
  'forward-zone:' \
  '  name: "."' \
  '  forward-addr: 1.1.1.1' \
  '  forward-addr: 1.0.0.1' \
  > /etc/unbound/unbound.conf
CMD ["unbound", "-d"]
