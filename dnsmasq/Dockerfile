FROM alpine:latest

RUN apk --no-cache add dnsmasq \
    && echo "conf-dir=/etc/dnsmasq,*.conf" > /etc/dnsmasq.conf

VOLUME ["/etc/dnsmasq"]

EXPOSE 53/tcp 53/udp

CMD ["dnsmasq"]