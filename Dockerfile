# Tunnel app for OpenHost — expose local web apps via Chisel reverse tunnel.

FROM docker.io/library/golang:1.24-alpine AS chisel-build
RUN apk add --no-cache git
RUN go install github.com/jpillora/chisel@latest

FROM docker.io/library/python:3.12-alpine

COPY --from=chisel-build /go/bin/chisel /usr/local/bin/chisel

RUN apk add --no-cache tini

COPY start.sh /opt/openhost/start.sh
COPY status_server.py /opt/openhost/status_server.py
RUN chmod 0755 /opt/openhost/start.sh /opt/openhost/status_server.py

EXPOSE 8080

ENTRYPOINT ["tini", "--", "/opt/openhost/start.sh"]
